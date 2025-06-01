import app from "./app.js";
import dotenv from "dotenv";

dotenv.config();

// const PORT = process.env.PORT || "5000";
const PORT = process.env.PORT || 3000;
const ENV = process.env.NODE_ENV || "development";

const startServer = async () => {
  try {    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV}`);
      console.log(`📱 Client URL: ${process.env.CLIENT_URL}`);
      console.log(`🔗 Server URL: ${process.env.SERVER_URL}`);
      console.log(`📋 API Documentation: ${process.env.SERVER_URL}/`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('💥 Unhandled Promise Rejection:', err);
  process.exit(1);
});

startServer();

app.listen(PORT, () => {
  console.log(`Server is running in ${ENV} mode on port ${PORT}`);
});
