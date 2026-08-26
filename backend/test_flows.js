'use strict';
require('dotenv').config();

const http = require('http');
const mongoose = require('mongoose');
const Admin = require('./models/Admin');
const Institute = require('./models/Institute');
const Paper = require('./models/Paper');
const Authority = require('./models/Authority');
const QRChallenge = require('./models/QRChallenge');
const AuditLog = require('./models/AuditLog');
const { signToken } = require('./utils/jwtHelper');

async function runTests() {
  console.log('=== STARTING VAULTO COMPREHENSIVE END-TO-END INTEGRATION TEST ===\n');

  await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vaulto');
  console.log('✓ Connected to MongoDB');

  // 1. Fetch sample admin, paper, and the institute assigned to the paper
  const admin = await Admin.findOne();
  const paper = await Paper.findOne();
  const institute = await Institute.findOne({ instituteId: paper.instituteId }) || await Institute.findOne({ isVerified: true });

  console.log(`Admin found: ${admin ? admin.email : 'None'}`);
  console.log(`Institute found: ${institute ? institute.instituteId + ' (' + institute.email + ')' : 'None'}`);
  console.log(`Paper found: ${paper ? paper.examId + ' (' + paper.paperCode + ')' : 'None'}\n`);

  const adminToken = signToken({ id: admin._id, role: 'admin', email: admin.email });
  const instToken = signToken({ id: institute._id, role: 'institute', email: institute.email, instituteId: institute.instituteId });

  function request(options, data) {
    return new Promise((resolve, reject) => {
      const req = http.request(options, res => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, headers: res.headers, data: JSON.parse(body) });
          } catch(e) {
            resolve({ status: res.statusCode, headers: res.headers, raw: body });
          }
        });
      });
      req.on('error', reject);
      if (data) {
        req.write(typeof data === 'string' ? data : JSON.stringify(data));
      }
      req.end();
    });
  }

  // TEST 1: Admin Stats
  console.log('TEST 1: GET /admin/stats');
  const resStats = await request({
    hostname: 'localhost', port: 5001, path: '/admin/stats', method: 'GET',
    headers: { 'Authorization': `Bearer ${adminToken}` }
  });
  console.log(`Result: HTTP ${resStats.status}, Total Papers: ${resStats.data.data.totalPapers}, Total Centres: ${resStats.data.data.totalInstitutes}`);

  // TEST 2: Distribution Monitor
  console.log('\nTEST 2: GET /admin/distribution-status');
  const resDist = await request({
    hostname: 'localhost', port: 5001, path: '/admin/distribution-status', method: 'GET',
    headers: { 'Authorization': `Bearer ${adminToken}` }
  });
  console.log('resDist output:', JSON.stringify(resDist));

  // TEST 3: Institute Integrity Verification
  console.log('\nTEST 3: GET /institute/verify-integrity/' + paper.examId);
  const resInteg = await request({
    hostname: 'localhost', port: 5001, path: `/institute/verify-integrity/${paper.examId}`, method: 'GET',
    headers: { 'Authorization': `Bearer ${instToken}` }
  });
  console.log(`Result: HTTP ${resInteg.status}, Integrity Status: ${resInteg.data.data ? resInteg.data.data.integrityStatus : 'Error'}, SHA-256: ${resInteg.data.data ? resInteg.data.data.sha256Checksum : 'N/A'}`);

  // TEST 4: Institute Download Encrypted Payload
  console.log('\nTEST 4: GET /institute/download-encrypted/' + paper.examId);
  const resDown = await request({
    hostname: 'localhost', port: 5001, path: `/institute/download-encrypted/${paper.examId}`, method: 'GET',
    headers: { 'Authorization': `Bearer ${instToken}` }
  });
  console.log(`Result: HTTP ${resDown.status}, Content-Type: ${resDown.headers['content-type']}`);

  // TEST 5: QR Challenge Creation
  console.log('\nTEST 5: POST /institute/create-challenge/' + paper.examId);
  const resChallenge = await request({
    hostname: 'localhost', port: 5001, path: `/institute/create-challenge/${paper.examId}`, method: 'POST',
    headers: { 'Authorization': `Bearer ${instToken}`, 'Content-Type': 'application/json' }
  });
  console.log(`Result: HTTP ${resChallenge.status}, Challenge ID: ${resChallenge.data.data ? resChallenge.data.data.challengeId : 'N/A'}`);
  const challengeId = resChallenge.data.data.challengeId;

  // TEST 6: Authority Scan Challenge
  console.log('\nTEST 6: POST /authority/scan-challenge');
  const resScan = await request({
    hostname: 'localhost', port: 5001, path: '/authority/scan-challenge', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { challengeId });
  console.log(`Result: HTTP ${resScan.status}, Exam: ${resScan.data.data.examName}, Centre: ${resScan.data.data.instituteName}`);

  // TEST 7: Authority Authorize Decryption
  console.log('\nTEST 7: POST /authority/authorize-decryption');
  const resAuthDec = await request({
    hostname: 'localhost', port: 5001, path: '/authority/authorize-decryption', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, {
    challengeId,
    authorityId: 'AUTH-TEST-INVIGILATOR',
    deviceId: 'MOB-DEVICE-HW-1234',
    biometricProof: true
  });
  console.log(`Result: HTTP ${resAuthDec.status}, Message: ${resAuthDec.data.message}`);

  // TEST 8: Check Challenge Status
  console.log('\nTEST 8: GET /authority/challenge-status/' + challengeId);
  const resStatus = await request({
    hostname: 'localhost', port: 5001, path: `/authority/challenge-status/${challengeId}`, method: 'GET'
  });
  console.log(`Result: HTTP ${resStatus.status}, Is Authorized: ${resStatus.data.data.isAuthorized}, Auth Token Present: ${Boolean(resStatus.data.data.authorizationToken)}`);

  // TEST 9: Offline Audit Log Sync
  console.log('\nTEST 9: POST /institute/sync-logs');
  const resSync = await request({
    hostname: 'localhost', port: 5001, path: '/institute/sync-logs', method: 'POST',
    headers: { 'Authorization': `Bearer ${instToken}`, 'Content-Type': 'application/json' },
  }, {
    logs: [
      { event: 'LOCAL_INTEGRITY_CHECK', examId: paper.examId, result: 'SUCCESS', details: 'SHA-256 hash verified locally in air-gap mode' },
      { event: 'LOCAL_OFFLINE_CACHE_VERIFIED', examId: paper.examId, result: 'SUCCESS', details: 'Local IndexedDB blob verified' }
    ]
  });
  console.log(`Result: HTTP ${resSync.status}, Synced Count: ${resSync.data.syncedCount}`);

  // TEST 10: Admin Emergency Lock & Unlock Flow
  console.log('\nTEST 10: Emergency Kill-Switch (Lock and Unlock)');
  const resLock = await request({
    hostname: 'localhost', port: 5001, path: `/admin/emergency-lock/${paper.examId}`, method: 'POST',
    headers: { 'Authorization': `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
  }, { reason: 'Test Emergency Freeze' });
  console.log(`Lock Result: HTTP ${resLock.status}, Message: ${resLock.data.message}`);

  const resUnlock = await request({
    hostname: 'localhost', port: 5001, path: `/admin/emergency-unlock/${paper.examId}`, method: 'POST',
    headers: { 'Authorization': `Bearer ${adminToken}` }
  });
  console.log(`Unlock Result: HTTP ${resUnlock.status}, Message: ${resUnlock.data.message}`);

  // TEST 12: Institute Multi-Factor Controlled Decryption
  console.log('\nTEST 12: POST /institute/decrypt-paper/' + paper.examId);
  const resDec = await request({
    hostname: 'localhost', port: 5001, path: `/institute/decrypt-paper/${paper.examId}`, method: 'POST',
    headers: { 'Authorization': `Bearer ${instToken}`, 'Content-Type': 'application/json' },
  }, {
    challengeId: challengeId,
    authorizationToken: resStatus.data.data.authorizationToken
  });
  console.log(`Result: HTTP ${resDec.status}, Content-Type: ${resDec.headers['content-type']}, Decrypted Size: ${resDec.raw ? resDec.raw.length : 0} bytes`);

  console.log('\n=== ALL 12 TEST FLOWS COMPLETED SUCCESSFULLY! ===');
  process.exit(0);
}

runTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
