const mongoose = require('mongoose');

const authoritySchema = new mongoose.Schema({
  authorityId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
  },
  phone: {
    type: String,
    default: '',
    trim: true,
  },
  role: {
    type: String,
    enum: ['chief_invigilator', 'observer', 'exam_superintendent', 'district_officer'],
    default: 'chief_invigilator',
  },
  assignedInstituteId: {
    type: String,
    default: '',
    trim: true,
  },
  registeredDeviceId: {
    type: String,
    default: '',
    trim: true,
  },
  biometricRegistered: {
    type: Boolean,
    default: true,
  },
  status: {
    type: String,
    enum: ['active', 'suspended', 'revoked'],
    default: 'active',
  },
  lastAuthAt: {
    type: Date,
    default: null,
  },
}, { timestamps: true });

module.exports = mongoose.model('Authority', authoritySchema);
