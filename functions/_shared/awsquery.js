// Fake AWS Query-protocol surface for SES + SNS, the two services the stolen-key
// recon crowd hits most (GetSendQuota / GetSMSAttributes in the canary data). Lured
// via AWS_ENDPOINT_URL_SES / AWS_ENDPOINT_URL_SNS in .env and ses/sns endpoint
// overrides in .aws/config: anyone who sources the env or copies the profile has
// those calls land here instead of real AWS, so we capture the recon directly
// instead of only seeing the canary fire. SES/SNS Query calls are POST / with a
// urlencoded Action=; responses are the AWS XML Query shape. All synthetic.

const reqId = () => (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(16) + Math.random().toString(16).slice(2, 10)));
const XML_H = { 'Content-Type': 'text/xml', 'x-amzn-RequestId': reqId(), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const SES_NS = 'http://ses.amazonaws.com/doc/2010-12-01/';
const SNS_NS = 'http://sns.amazonaws.com/doc/2010-03-31/';

function wrap(action, ns, inner) {
  return `<${action}Response xmlns="${ns}">\n  <${action}Result>${inner}</${action}Result>\n  <ResponseMetadata><RequestId>${reqId()}</RequestId></ResponseMetadata>\n</${action}Response>\n`;
}

// action -> () => xml body (chosen to look like a live, modestly-used account)
const ACTIONS = {
  // ---- SES (v1 Query) ----
  GetSendQuota: () => wrap('GetSendQuota', SES_NS, `\n    <Max24HourSend>50000.0</Max24HourSend>\n    <MaxSendRate>14.0</MaxSendRate>\n    <SentLast24Hours>${300 + Math.floor(Math.random() * 400)}.0</SentLast24Hours>\n  `),
  GetAccountSendingEnabled: () => wrap('GetAccountSendingEnabled', SES_NS, `<Enabled>true</Enabled>`),
  GetSendStatistics: () => wrap('GetSendStatistics', SES_NS, `<SendDataPoints><member><Timestamp>2026-11-28T06:00:00Z</Timestamp><DeliveryAttempts>${100 + Math.floor(Math.random() * 200)}</DeliveryAttempts><Bounces>2</Bounces><Complaints>0</Complaints><Rejects>1</Rejects></member></SendDataPoints>`),
  ListIdentities: () => wrap('ListIdentities', SES_NS, `<Identities><member>records.internal</member><member>noreply@records.internal</member></Identities>`),
  ListVerifiedEmailAddresses: () => wrap('ListVerifiedEmailAddresses', SES_NS, `<VerifiedEmailAddresses><member>noreply@records.internal</member></VerifiedEmailAddresses>`),
  // ---- SNS (Query) ----
  GetSMSAttributes: () => wrap('GetSMSAttributes', SNS_NS, `<attributes><entry><key>MonthlySpendLimit</key><value>1.00</value></entry><entry><key>DeliveryStatusSuccessSamplingRate</key><value>0</value></entry><entry><key>DefaultSMSType</key><value>Transactional</value></entry></attributes>`),
  GetSMSSandboxAccountStatus: () => wrap('GetSMSSandboxAccountStatus', SNS_NS, `<IsInSandbox>false</IsInSandbox>`),
  CheckIfPhoneNumberIsOptedOut: () => wrap('CheckIfPhoneNumberIsOptedOut', SNS_NS, `<isOptedOut>false</isOptedOut>`),
  ListTopics: () => wrap('ListTopics', SNS_NS, `<Topics><member><TopicArn>arn:aws:sns:us-east-2:271943558210:records-alerts</TopicArn></member></Topics>`),
  GetSMSAttributesResult: null,
};

function pickNs(action) { return /SMS|Topic|Subscri|Publish|PhoneNumber|Endpoint|Platform/.test(action) ? SNS_NS : SES_NS; }

// Returns {response,row,alert} for an SES/SNS Query POST, else null (body untouched
// unless this is our shape: POST / with a urlencoded Action=).
export async function handleAwsQuery(request, env, m) {
  if (request.method !== 'POST') return null;
  const url = new URL(request.url);
  if (url.pathname !== '/') return null;
  const ct = (request.headers.get('Content-Type') || '').toLowerCase();
  if (!ct.includes('x-www-form-urlencoded')) return null;

  let raw = '';
  try { raw = await request.text(); } catch {}
  const params = new URLSearchParams(raw);
  const action = params.get('Action');
  if (!action) return null;

  // which AKIA signed it (Authorization: AWS4-HMAC-SHA256 Credential=AKIA.../...)
  const auth = request.headers.get('Authorization') || '';
  const km = auth.match(/Credential=([A-Z0-9]{16,})\//);
  const key = km ? km[1] : '';
  const svc = pickNs(action) === SNS_NS ? 'sns' : 'ses';

  let body, status;
  if (ACTIONS[action]) { body = ACTIONS[action](); status = 200; }
  else {
    status = 400;
    body = `<ErrorResponse xmlns="${pickNs(action)}">\n  <Error><Type>Sender</Type><Code>InvalidAction</Code><Message>Could not find operation ${action} for the service.</Message></Error>\n  <RequestId>${reqId()}</RequestId>\n</ErrorResponse>\n`;
  }
  const response = new Response(body, { status, headers: { ...XML_H, 'x-amzn-RequestId': reqId() } });
  const row = {
    host: url.hostname, method: 'POST', path: `/${svc}:${action}`, query: '',
    tier: '', key, status, body: raw.slice(0, 1500), ...m,
  };
  return { response, row, alert: true };
}
