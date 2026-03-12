const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log(`✅ MongoDB kết nối thành công: ${conn.connection.host}`);
  } catch (error) {
    console.error(`❌ MongoDB lỗi kết nối: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
