const mongoose = require('mongoose');

const registeredDeviceSchema = new mongoose.Schema({
  deviceId:     { type: String, required: true, trim: true },
  deviceName:   { type: String, default: 'Workstation' },
  deviceType:   { type: String, default: 'desktop' },
  fingerprint:  { type: String, default: '' },
  registeredAt: { type: Date, default: Date.now },
  lastSeenAt:   { type: Date, default: Date.now },
  isApproved:   { type: Boolean, default: true },
}, { _id: false });

const instituteSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: 8,
    },
    instituteId: {
      type: String,
      required: [true, 'Institute ID is required'],
      unique: true,
      trim: true,
    },
    name: {
      type: String,
      trim: true,
      default: '',
    },
    district: {
      type: String,
      trim: true,
      default: '',
    },
    status: {
      type: String,
      enum: ['active', 'blocked', 'suspended'],
      default: 'active',
    },
    registeredDevices: {
      type: [registeredDeviceSchema],
      default: [],
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    lastLoginAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Institute', instituteSchema);
