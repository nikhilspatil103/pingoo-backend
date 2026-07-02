require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');
const { GoogleAuth } = require('google-auth-library');
const serviceAccount = require('./firebase-service-account.json');

async function testPush() {
  await mongoose.connect(process.env.MONGODB_URI);
  
  const user = await User.findOne({ pushToken: { $ne: null, $not: /^ExponentPushToken/ } }).select('name pushToken').sort({ lastSeen: -1 }).lean();
  console.log('Sending test notification to:', user.name);
  console.log('Token:', user.pushToken.substring(0, 40) + '...');
  
  const auth = new GoogleAuth({
    credentials: serviceAccount,
    scopes: ['https://www.googleapis.com/auth/firebase.messaging'],
  });
  
  const client = await auth.getClient();
  const accessToken = (await client.getAccessToken()).token;
  console.log('Got access token:', accessToken ? 'YES' : 'NO');
  
  const message = {
    message: {
      token: user.pushToken,
      notification: { title: 'Test 🔔', body: 'Notifications are working!' },
      data: { type: 'test' },
      android: { priority: 'high', notification: { channel_id: 'default', sound: 'default' } },
    },
  };

  const url = `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accessToken },
    body: JSON.stringify(message),
  });
  
  const result = await res.text();
  console.log('Status:', res.status);
  console.log('Response:', result);
  
  await mongoose.disconnect();
}

testPush().catch(e => console.error(e));
