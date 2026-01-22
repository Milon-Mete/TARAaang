require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Built-in Node module for Hashing

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "greenhaven_secret_key_123";
const ADMIN_SECRET_CODE = process.env.ADMIN_SECRET || "admin123";

// --- PAYU CONFIGURATION ---
const PAYU_KEY = process.env.PAYU_KEY
const PAYU_SALT = process.env.PAYU_SALT

// --- 1. CONFIGURATION & MIDDLEWARE ---
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Required for PayU form posts if you use direct callbacks

// --- 2. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch((err) => { console.error('DB Connection Error:', err); process.exit(1); });

// --- 3. CLOUDINARY CONFIG ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: { folder: 'ecommerce_products', allowed_formats: ['jpg', 'png', 'jpeg', 'webp'] },
});
const upload = multer({ storage: storage });

// --- 4. SECURITY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') next();
    else res.status(403).json({ error: "Admins Only" });
};

// ======================================================
// --- 5. SCHEMAS ---
// ======================================================

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, default: "General" },
    description: { type: String, default: "" },
    imageUrl: { type: String, default: "" },
    galleryImages: [{ type: String }],
    pricingMode: { type: String, enum: ['per_item', 'per_area', 'per_length', 'per_weight'], default: 'per_item' },
    unitLabel: { type: String, default: "pc" },
    basePrice: { type: Number, default: 0 },
    variants: [{
        variety: { type: String, default: "Standard" },
        color: { type: String, default: "" },
        height: { type: String, default: "" },
        price: { type: Number, default: 0 },
        countInStock: { type: Number, default: 0 },
        packageWeight: { type: Number, default: 0 }
    }]
}, { timestamps: true });

const Product = mongoose.model('Product', ProductSchema);

const OrderSchema = new mongoose.Schema({
    shortToken: { type: String, required: true },
    customerName: { type: String, required: true },
    customerPhone: { type: String, required: true },
    items: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        name: String,
        qty: Number,
        price: Number,
        returnedQty: { type: Number, default: 0 }
    }],
    subtotal: { type: Number, default: 0 },
    taxAmount: { type: Number, default: 0 },
    deliveryFee: { type: Number, default: 0 },
    totalAmount: { type: Number, required: true },
    paymentStatus: { type: String, enum: ['PAID', 'DUE', 'CANCELLED', 'PARTIAL_RETURN'], default: 'DUE' },
    transactionId: { type: String, default: '' },
    isCollected: { type: Boolean, default: false },
    orderType: { type: String, enum: ['pickup', 'delivery'], default: 'pickup' },
    address: { type: String, default: "" },
    refundedAmount: { type: Number, default: 0 },
    status: { type: String, default: 'ACTIVE' }
}, { timestamps: true });

const Order = mongoose.model('Order', OrderSchema);


const CustomerSchema = new mongoose.Schema({
    name: { type: String, default: "Guest" },
    phone: { type: String, required: true, unique: true },
    password: { type: String },
    otp: { type: String },
    otpExpires: { type: Date },
    isVerified: { type: Boolean, default: false },
    role: { type: String, default: 'customer' }
}, { timestamps: true });

const Customer = mongoose.model('Customer', CustomerSchema);


// ======================================================
// --- 6. ROUTES ---
// ======================================================

app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password, adminCode } = req.body;
        if (adminCode !== ADMIN_SECRET_CODE) return res.status(403).json({ error: "Forbidden: Incorrect Admin Code" });
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: "Email exists" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, role: 'admin' });
        await newUser.save();
        res.status(201).json({ message: "Admin account created successfully!" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.role !== 'admin') return res.status(403).json({ error: "Access Denied" });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find().sort({ _id: -1 });
        res.json(products);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/products/validate-stock', async (req, res) => {
    try {
        const { items } = req.body;
        const outOfStockItems = [];

        for (const item of items) {
            const product = await Product.findById(item._id || item.id);
            if (!product) { outOfStockItems.push(`Unknown Item`); continue; }

            let availableStock = 0;
            let itemName = product.name;

            if (item.variant && product.variants.length > 0) {
                const targetVariant = product.variants.find(v =>
                    (v._id && item.variant._id && v._id.toString() === item.variant._id) ||
                    (v.variety === item.variant.variety && v.color === item.variant.color && v.height === item.variant.height)
                );

                if (targetVariant) {
                    availableStock = targetVariant.countInStock;
                    itemName = `${product.name} (${targetVariant.variety} ${targetVariant.color || ''} ${targetVariant.height || ''})`;
                }
            } else if (product.variants.length > 0) {
                availableStock = product.variants[0].countInStock;
            } else {
                availableStock = product.countInStock || 0;
            }

            if (availableStock < item.qty) {
                outOfStockItems.push(`${itemName} (Stock: ${availableStock})`);
            }
        }

        if (outOfStockItems.length > 0) {
            return res.status(409).json({ error: "Stock validation failed", outOfStockItems: outOfStockItems });
        }
        res.status(200).json({ message: "Stock available" });
    } catch (error) { res.status(500).json({ error: "Server error checking stock" }); }
});

const uploadFields = upload.fields([{ name: 'image', maxCount: 1 }, { name: 'gallery', maxCount: 3 }]);

app.post('/api/products', authenticateToken, requireAdmin, uploadFields, async (req, res) => {
    try {
        let mainImageUrl = "https://res.cloudinary.com/dvlwzfsd0/image/upload/v1766831829/no_product_jjmm9m.png";
        if (req.files && req.files['image']) mainImageUrl = req.files['image'][0].path;

        let galleryUrls = [];
        if (req.files && req.files['gallery']) galleryUrls = req.files['gallery'].map(file => file.path);

        let variants = [];
        if (req.body.variants) variants = typeof req.body.variants === 'string' ? JSON.parse(req.body.variants) : req.body.variants;

        let basePrice = 0;
        if (variants.length > 0) {
            const prices = variants.map(v => v.price).filter(p => p > 0);
            if (prices.length > 0) basePrice = Math.min(...prices);
        }

        const newProduct = new Product({ ...req.body, imageUrl: mainImageUrl, galleryImages: galleryUrls, variants: variants, basePrice: basePrice });
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/products/:id', authenticateToken, requireAdmin, uploadFields, async (req, res) => {
    try {
        const updateData = { ...req.body };
        if (req.files && req.files['image']) updateData.imageUrl = req.files['image'][0].path;
        if (req.files && req.files['gallery']) updateData.galleryImages = req.files['gallery'].map(file => file.path);
        if (updateData.variants) {
            updateData.variants = typeof updateData.variants === 'string' ? JSON.parse(updateData.variants) : updateData.variants;
            const prices = updateData.variants.map(v => v.price).filter(p => p > 0);
            if (prices.length > 0) updateData.basePrice = Math.min(...prices);
        }
        const updatedProduct = await Product.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true });
        res.json(updatedProduct);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "Deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ======================================================
// --- 7. ORDER & PAYMENT PROCESSING (PAYU) ---
// ======================================================

// --- NEW ROUTE: Generate PayU Hash ---
// 1. Generate Hash & Info for Frontend Form
// --- 1. Generate PayU Hash ---
// ======================================================
// --- 7. ORDER & PAYMENT PROCESSING (SECURE FLOW) ---
// ======================================================

// --- 1. CREATE ORDER (Always starts as DUE/PENDING) ---
// This is now called BEFORE payment to reserve stock and get an Order ID
app.post('/api/orders', async (req, res) => {
    try {
        const { items, customerName, customerPhone, orderType, address } = req.body;

        let calculatedSubtotal = 0;
        let secureItems = [];
        const shortToken = Math.floor(1000 + Math.random() * 9000).toString();

        // Stock Deduction Logic
        for (const item of items) {
            const product = await Product.findById(item.id || item._id);
            if (!product) continue;

            let price = product.basePrice;
            let variantLabel = "";
            let targetVariant = null;

            // Find Variant
            if (item.variant && product.variants.length > 0) {
                targetVariant = product.variants.find(v => v.variety === item.variant.variety && v.color === item.variant.color);
            }

            if (targetVariant) {
                // Check stock (Basic check, consider atomic decrement for high volume)
                if (targetVariant.countInStock < item.qty) {
                    return res.status(400).json({ error: `Out of stock: ${product.name} (${targetVariant.variety})` });
                }
                targetVariant.countInStock -= item.qty;
                price = targetVariant.price;
                variantLabel = ` ${targetVariant.variety}`;
            } else {
                if (product.countInStock < item.qty) {
                    return res.status(400).json({ error: `Out of stock: ${product.name}` });
                }
                product.countInStock -= item.qty;
            }
            await product.save();

            calculatedSubtotal += (price * item.qty);
            secureItems.push({ product: product._id, name: product.name + variantLabel, qty: item.qty, price, returnedQty: 0 });
        }

        let deliveryFee = orderType === 'delivery' ? 40 : 0;
        let totalAmount = calculatedSubtotal + deliveryFee;

        // SECURITY FIX: HARDCODE STATUS TO 'DUE'
        // We ignore any 'paymentStatus' sent from frontend
        const initialStatus = 'DUE';

        const newOrder = new Order({
            shortToken, customerName, customerPhone, orderType, address,
            items: secureItems, subtotal: calculatedSubtotal, deliveryFee, totalAmount,
            paymentStatus: initialStatus, // <--- FORCED SECURE STATUS
            transactionId: '',
            isCollected: false
        });

        await newOrder.save();

        // Return the Order ID so frontend can use it for PayU
        res.status(201).json({ success: true, order: newOrder, orderId: newOrder._id });

    } catch (e) { res.status(500).json({ error: e.message }); }
});


// --- 2. GENERATE PAYU HASH (Now requires Order ID) ---
app.post('/api/payment/generate-hash', async (req, res) => {
    try {
        // We now receive the orderId created in step 1
        const { orderId, customerName, customerPhone } = req.body;

        // Fetch the REAL order from DB to get the amount
        // (Prevents frontend from lying about the price)
        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ error: "Order not found" });

        const finalTotal = order.totalAmount; // Trust DB, not frontend

        // Auto-generate email for PayU requirement
        const generatedEmail = `${customerPhone}@taraaang.com`;

        // -- Prepare PayU Data --
        // USE ORDER ID AS TRANSACTION ID
        const txnid = orderId.toString();
        const productinfo = "TARAAANG LANDSCAPE ORDER";
        const firstname = customerName.split(' ')[0] || "Customer";

        // -- Generate Hash (sha512) --
        // Formula: key|txnid|amount|productinfo|firstname|email|||||||||||salt
        const hashString = `${PAYU_KEY}|${txnid}|${finalTotal}|${productinfo}|${firstname}|${generatedEmail}|||||||||||${PAYU_SALT}`;
        const hash = crypto.createHash('sha512').update(hashString).digest('hex');

        res.json({
            key: PAYU_KEY,
            txnid,
            amount: finalTotal,
            productinfo,
            firstname,
            email: generatedEmail,
            phone: customerPhone,
            hash
        });

    } catch (e) { res.status(500).json({ error: e.message }); }
});


// --- 3. HANDLE PAYU CALLBACK (Updates DB directly) ---
app.post('/api/payment/callback', async (req, res) => {
    try {
        console.log("🔔 PayU Callback Received:", req.body);

        const { txnid, amount, productinfo, firstname, email, status, hash, mihpayid } = req.body;

        // 1. VERIFY HASH (Security Check)
        const reverseHashString = `${PAYU_SALT}|${status}|||||||||||${email}|${firstname}|${productinfo}|${amount}|${txnid}|${PAYU_KEY}`;
        const calculatedHash = crypto.createHash('sha512').update(reverseHashString).digest('hex');

        const FRONTEND_URL = process.env.FRONTEND_URL || "http://127.0.0.1:5500/TARAaang";

        if (calculatedHash !== hash) {
            console.error("❌ Hash Mismatch");
            return res.redirect(`${FRONTEND_URL}/cart.html?status=error&msg=HashMismatch`);
        }

        if (status === 'success') {
            console.log(`✅ Payment Success for Order ID: ${txnid}`);

            // 2. UPDATE ORDER STATUS IN DB
            // txnid IS the orderId because we set it that way in step 2
            await Order.findByIdAndUpdate(txnid, {
                paymentStatus: 'PAID',
                transactionId: mihpayid // Save PayU's reference ID
            });

            // Redirect to success page
            res.redirect(`${FRONTEND_URL}/cart.html?status=success&txnId=${txnid}&amt=${amount}`);
        } else {
            console.log(`❌ Payment Failed`);
            // Optional: You might want to release stock here if payment fails
            res.redirect(`${FRONTEND_URL}/cart.html?status=failed`);
        }
    } catch (e) {
        console.error("Callback Error:", e);
        const FRONTEND_URL = process.env.FRONTEND_URL || "http://127.0.0.1:5500/TARAaang";
        res.redirect(`${FRONTEND_URL}/cart.html?status=error`);
    }
});
app.put('/api/orders/update-payment', async (req, res) => {
    try {
        const { orderId, paymentId, status } = req.body;
        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ error: "Order not found" });

        order.paymentStatus = status;
        order.transactionId = paymentId;
        await order.save();

        res.json({ success: true, message: "Payment updated", order });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- NEW ROUTE: Handle PayU Response (Success/Failure) ---
app.post('/api/payment/callback', async (req, res) => {
    try {
        console.log("--------------------------------");
        console.log("🔔 PayU Callback Received");
        console.log("Payload:", req.body); // Log the full response from PayU

        const { txnid, amount, productinfo, firstname, email, status, hash } = req.body;

        // ⚠️ CRITICAL: Set this to your frontend address. 
        // If you use VS Code Live Server, it is usually http://127.0.0.1:5500 or http://localhost:5500
        const frontendUrl = process.env.FRONTEND_URL || "http://127.0.0.1:5500";

        // 1. Verify Reverse Hash for Security
        // Formula: salt|status|||||||||||email|firstname|productinfo|amount|txnid|key
        const reverseHashString = `${PAYU_SALT}|${status}|||||||||||${email}|${firstname}|${productinfo}|${amount}|${txnid}|${PAYU_KEY}`;
        const calculatedHash = crypto.createHash('sha512').update(reverseHashString).digest('hex');

        // Debugging Hash (Remove in production)
        // console.log("Calc Hash:", calculatedHash);
        // console.log("Recv Hash:", hash);

        if (calculatedHash !== hash) {
            console.error("❌ Security Error: Hash Mismatch");
            return res.redirect(`${frontendUrl}/cart.html?status=error&msg=HashMismatch`);
        }

        if (status === 'success') {
            console.log(`✅ Payment Success for txn: ${txnid}`);
            // Redirect back to frontend with the txnId. 
            // The frontend will detect this and create the order in the DB.
            res.redirect(`${frontendUrl}/cart.html?status=success&txnId=${txnid}&amt=${amount}`);
        } else {
            console.log(`❌ Payment Failed/Cancelled for txn: ${txnid}`);
            res.redirect(`${frontendUrl}/cart.html?status=failed`);
        }
    } catch (e) {
        console.error("❌ Callback Exception:", e);
        const frontendUrl = process.env.FRONTEND_URL || "http://127.0.0.1:5500";
        res.redirect(`${frontendUrl}/cart.html?status=error`);
    }
});

// server.js

// --- MARK ORDER AS COLLECTED ---
app.put('/api/orders/collect/:id', async (req, res) => {
    try {
        const orderId = req.params.id;

        // Find and update the order
        const order = await Order.findByIdAndUpdate(
            orderId,
            {
                isCollected: true,
                status: 'COMPLETED' // Optional: Mark as fully complete
            },
            { new: true } // Return the updated document
        );

        if (!order) {
            return res.status(404).json({ error: "Order not found" });
        }

        res.json({ success: true, order });
    } catch (e) {
        console.error("Collect Error:", e);
        res.status(500).json({ error: e.message });
    }
});

// --- NEW ROUTE: Get Single Order (Public) ---
// This is required for the Success Page to render the receipt
app.get('/api/orders/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (order) {
            res.json(order);
        } else {
            res.status(404).json({ message: 'Order not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});

app.put('/api/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const updatedOrder = await Order.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true });
        res.json(updatedOrder);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/orders/collect/:id', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(req.params.id, { isCollected: true }, { new: true });
        res.json({ success: true, order });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/orders/track/:phone', async (req, res) => {
    try {
        const orders = await Order.find({ customerPhone: req.params.phone }).sort({ createdAt: -1 });
        if (!orders || orders.length === 0) return res.status(404).json({ error: "No orders found" });
        res.json(orders);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Add this with your other Admin routes
app.get('/api/orders', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // Fetch all orders, newest first
        const orders = await Order.find().sort({ createdAt: -1 });
        res.json(orders);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ====================================================================
// --- FIXED: SAFE RETURN LOGIC (Active Orders Stay Active) ---
// ====================================================================
app.post('/api/orders/return-cancel', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { orderId, itemsToReturn, actionType } = req.body;
        // actionType: 'CANCEL_ORDER' (Full) OR 'RETURN_ITEMS' (Partial)

        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ error: "Order not found" });

        // 1. Check Global Order Status
        if (order.paymentStatus === 'CANCELLED') {
            return res.status(400).json({ error: "Order is already completely cancelled." });
        }

        let currentRefundAmount = 0;

        // 2. Process Items
        const itemsToProcess = (actionType === 'CANCEL_ORDER')
            ? order.items.map(i => ({ orderItemId: i._id.toString(), qty: (i.qty - (i.returnedQty || 0)) }))
            : itemsToReturn;

        for (const returnItem of itemsToProcess) {
            const dbItem = order.items.id(returnItem.orderItemId);
            if (!dbItem) continue;

            const qtyToReturn = Number(returnItem.qty);
            if (qtyToReturn <= 0) continue;

            const availableToReturn = dbItem.qty - (dbItem.returnedQty || 0);
            if (qtyToReturn > availableToReturn) {
                return res.status(400).json({
                    error: `Cannot return ${qtyToReturn} of ${dbItem.name}. Only ${availableToReturn} remaining.`
                });
            }

            // Update item-level returns
            dbItem.returnedQty = (dbItem.returnedQty || 0) + qtyToReturn;
            currentRefundAmount += (dbItem.price * qtyToReturn);

            // RESTOCK
            const product = await Product.findById(dbItem.product);
            if (product) {
                let variantFound = false;
                if (product.variants && product.variants.length > 0) {
                    const targetVariant = product.variants.find(v =>
                        dbItem.name.includes(v.variety) && dbItem.price === v.price
                    );
                    if (targetVariant) {
                        targetVariant.countInStock += qtyToReturn;
                        variantFound = true;
                    } else {
                        product.variants[0].countInStock += qtyToReturn;
                        variantFound = true;
                    }
                }
                if (!variantFound) {
                    product.countInStock += qtyToReturn;
                }
                await product.save();
            }
        }

        // 3. Update Order Totals
        order.refundedAmount = (order.refundedAmount || 0) + currentRefundAmount;

        // 4. CRITICAL STATUS LOGIC FIX:
        const isFullyReturned = order.items.every(item => item.qty === item.returnedQty);

        if (isFullyReturned || actionType === 'CANCEL_ORDER') {
            order.paymentStatus = 'CANCELLED';
            order.isCollected = false; // Remove from "Done" tab
        }

        await order.save();

        res.json({
            success: true,
            message: isFullyReturned ? "Order Cancelled & Restocked" : "Items Returned & Restocked",
            refundedAmount: currentRefundAmount,
            order
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});


// ======================================================
// --- CUSTOMER AUTH ROUTES ---
// ======================================================

async function sendSMS(phone, otp) {
    console.log(`[MOCK SMS] Sending OTP to ${phone}: ${otp}`);
    return true;
}

app.post('/api/customer/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ error: "Phone number required" });

        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        let customer = await Customer.findOne({ phone });
        if (!customer) {
            customer = new Customer({ phone, otp, otpExpires });
        } else {
            customer.otp = otp;
            customer.otpExpires = otpExpires;
        }
        await customer.save();

        await sendSMS(phone, otp);
        res.json({ message: "OTP sent successfully", dev_otp: otp });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/customer/verify-otp', async (req, res) => {
    try {
        const { phone, otp } = req.body;
        const customer = await Customer.findOne({ phone, otp, otpExpires: { $gt: Date.now() } });

        if (!customer) return res.status(400).json({ error: "Invalid OTP" });

        customer.otp = undefined;
        customer.isVerified = true;
        await customer.save();

        const token = jwt.sign({ id: customer._id }, JWT_SECRET, { expiresIn: '30d' });
        const nameRequired = !customer.name || customer.name === "Guest";

        res.json({
            message: "Success",
            token,
            nameRequired,
            user: { name: customer.name || "", phone: customer.phone }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/customer/update-profile', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: "Name is required" });

        const customer = await Customer.findByIdAndUpdate(
            req.user.id,
            { name: name },
            { new: true }
        );

        res.json({
            message: "Profile updated",
            user: {
                id: customer._id,
                phone: customer.phone,
                name: customer.name,
                role: 'customer'
            }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/customer/set-password', authenticateToken, async (req, res) => {
    try {
        const { password, name } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        await Customer.findByIdAndUpdate(req.user.id, {
            password: hashedPassword,
            name: name || "Valued Customer"
        });

        res.json({ message: "Password set successfully" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/customer/login', async (req, res) => {
    try {
        const { phone, password } = req.body;

        const customer = await Customer.findOne({ phone });
        if (!customer) return res.status(404).json({ error: "Customer not found" });
        if (!customer.password) return res.status(400).json({ error: "Password not set. Login via OTP first." });

        const isMatch = await bcrypt.compare(password, customer.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid password" });

        const token = jwt.sign({ id: customer._id, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            token,
            user: { id: customer._id, phone: customer.phone, name: customer.name, role: 'customer' }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
