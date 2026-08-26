const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    index: true,
  },
  event: {
    type: String,
    required: true,
    trim: true,
    index: true,
  },
  actorType: {
    type: String,
    enum: ['admin', 'institute', 'authority', 'system'],
    required: true,
  },
  actorId: {
    type: String,
    required: true,
    trim: true,
  },
  targetType: {
    type: String,
    enum: ['paper', 'institute', 'exam', 'device', 'authority', 'security', 'system'],
    default: 'system',
  },
  targetId: {
    type: String,
    default: '',
    trim: true,
  },
  examId: {
    type: String,
    default: '',
    trim: true,
  },
  instituteId: {
    type: String,
    default: '',
    trim: true,
  },
  deviceId: {
    type: String,
    default: '',
    trim: true,
  },
  result: {
    type: String,
    enum: ['SUCCESS', 'FAILURE', 'WARNING', 'BLOCKED', 'INFO'],
    default: 'SUCCESS',
  },
  details: {
    type: String,
    default: '',
  },
  ipAddress: {
    type: String,
    default: '',
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  syncedFromOffline: {
    type: Boolean,
    default: false,
  },
}, { timestamps: true });

module.exports = mongoose.model('AuditLog', auditLogSchema);
