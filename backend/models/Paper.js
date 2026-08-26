const mongoose = require('mongoose');

const paperSchema = new mongoose.Schema({
  // Identifiers
  examId:             { type: String, required: true, unique: true, trim: true },
  paperCode:          { type: String, required: true, trim: true },   // numbers-only code
  examName:           { type: String, required: true, trim: true },
  subject:            { type: String, required: true, trim: true },   // alias/display
  instituteId:        { type: String, required: true, trim: true },   // primary assigned or uploader institute
  assignedInstitutes: { type: [String], default: [] },                // all authorized exam centres

  // Timing
  examDate:    { type: Date, required: true },
  unlockTime:  { type: Date, required: true },
  uploadTime:  { type: Date, default: Date.now },

  // File & Cryptographic Metadata
  originalName:   { type: String, default: '' },
  encryptedData:  { type: String, default: '' },  // base64-encoded AES-256-CBC ciphertext
  encryptionKey:  { type: String, default: '' },  // hex-encoded 256-bit key
  encryptionIV:   { type: String, default: '' },  // hex-encoded IV
  sha256Checksum: { type: String, default: '' },  // SHA-256 integrity checksum
  fileSizeBytes:  { type: Number, default: 0 },

  // Security & Status Controls
  status:              { type: String, enum: ['locked', 'unlocked', 'accessed', 'revoked'], default: 'locked' },
  isEmergencyLocked:   { type: Boolean, default: false },
  emergencyLockReason: { type: String, default: '' },
  accessedBy:          { type: [String], default: [] },
  printCount:          { type: Number, default: 0 },
}, { timestamps: true });

// Pre-save hook to ensure assignedInstitutes contains primary instituteId
paperSchema.pre('save', function (next) {
  if (this.instituteId && (!this.assignedInstitutes || this.assignedInstitutes.length === 0)) {
    this.assignedInstitutes = [this.instituteId];
  } else if (this.instituteId && !this.assignedInstitutes.includes(this.instituteId)) {
    this.assignedInstitutes.push(this.instituteId);
  }
  next();
});

module.exports = mongoose.model('Paper', paperSchema);
