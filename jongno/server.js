/**
 * 노무법인 종로 홈페이지 서버 (Express) — 프론트(public/) + API 통합, 배포용
 * (검증된 운영 코드 기반 개조판: 변호사 → 공인노무사 특화)
 * ------------------------------------------------------------
 *  npm install express cors node-fetch nodemailer dotenv
 *  node server.example.js
 *
 *  .env 예시:
 *    OPENAI_API_KEY=sk-...            // Realtime + 요약용
 *    LAW_OC=your_open_law_key         // open.law.go.kr 판례 인증키
 *    SMTP_HOST=smtp.naver.com
 *    SMTP_USER=lawyer@naver.com
 *    SMTP_PASS=앱비밀번호
 *    LAWYER_EMAIL=kkd@jnhrm.co.kr     // 상담요약 수신 노무사 메일
 *
 *  ⚠️ 반드시 HTTPS로 서빙하세요. 브라우저 마이크(getUserMedia)는 HTTPS에서만 동작합니다.
 * ------------------------------------------------------------
 */
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import nodemailer from 'nodemailer';

const app = express();

/* ============================================================
   [보안] API 남용 방지 — 외부 라이브러리 없이 순수 코드로 구현
   1층: IP당 시간창 제한 / 2층: 서비스 전체 하루 총량 제한
   3층은 OpenAI 대시보드의 월 예산 한도(코드 외부)
   ============================================================ */
app.set('trust proxy', 1); // Cloudtype 프록시 뒤에서 실제 방문자 IP 인식

// CORS: 운영 도메인만 브라우저 교차 호출 허용 (같은 도메인 접속은 CORS와 무관하게 항상 정상)
const ALLOWED_ORIGINS = [
  // ⚠️ 클라우드타입 배포 후 발급되는 주소로 교체하세요 (예: https://port-0-jongno-labor-xxxx.sel3.cloudtype.app)
  'https://port-0-jongno-labor.sel3.cloudtype.app',
  // 도메인 연결 시 여기에 추가: 'https://www.jnhrm.co.kr',
];
app.use(cors({ origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin)) }));

const getIP = (req) => (req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown').trim();

// 1층: IP당 제한 (슬라이딩 윈도우)
const ipHits = new Map();
function ipLimit(name, max, windowMs = 60 * 60 * 1000) {
  return (req, res, next) => {
    const key = `${name}:${getIP(req)}`;
    const now = Date.now();
    const arr = (ipHits.get(key) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) {
      return res.status(429).json({ error: '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.' });
    }
    arr.push(now); ipHits.set(key, arr);
    if (ipHits.size > 5000) { // 메모리 청소
      for (const [k, v] of ipHits) if (!v.some(t => now - t < windowMs)) ipHits.delete(k);
    }
    next();
  };
}

// 2층: 하루 총량 제한 (자정 리셋, 한국시간 기준) — 리얼타임 상담 하루 10회
const DAILY_CAPS = { realtime: 10, voicechat: 600, finish: 15, chat: 300 };
let dailyState = { date: '', counts: {} };
function dailyCap(name) {
  return (req, res, next) => {
    const today = new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10);
    if (dailyState.date !== today) dailyState = { date: today, counts: {} };
    const used = dailyState.counts[name] || 0;
    if (used >= DAILY_CAPS[name]) {
      return res.status(429).json({ error: '오늘 상담 서비스 이용량이 모두 소진되었습니다. 전화(02-6929-4540)로 상담해주세요.' });
    }
    dailyState.counts[name] = used + 1;
    next();
  };
}

// 리얼타임 상담 비밀번호 게이트 (환경변수 REALTIME_PW로 변경 가능, 기본 2026)
function pwGate(req, res, next) {
  const pw = req.query.pw || req.headers['x-consult-pw'] || '';
  if (pw !== (process.env.REALTIME_PW || '2026')) {
    return res.status(401).json({ error: '상담 비밀번호가 올바르지 않습니다.' });
  }
  next();
}

// Cloudflare Turnstile 봇 검증 — TURNSTILE_SECRET 환경변수가 있을 때만 작동 (없으면 통과)
async function turnstileGate(req, res, next) {
  const secret = process.env.TURNSTILE_SECRET;
  if (!secret) return next();
  const token = req.query.ts || req.headers['x-turnstile-token'] || '';
  if (!token) return res.status(403).json({ error: '보안 확인이 필요합니다. 새로고침 후 다시 시도해주세요.' });
  try {
    const vr = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret, response: token, remoteip: getIP(req) }),
    });
    const v = await vr.json();
    if (!v.success) return res.status(403).json({ error: '보안 확인에 실패했습니다. 새로고침 후 다시 시도해주세요.' });
    next();
  } catch { return res.status(403).json({ error: '보안 확인 오류. 잠시 후 다시 시도해주세요.' }); }
}

app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));   // 프론트(public/index.html) 서빙

const OPENAI_KEY = process.env.OPENAI_API_KEY;
const LAW_OC = process.env.LAW_OC;

/* 상담 지식 베이스 — 노무 상담 19,718건(노동자 14,913 / 사업주 4,805)의 분류·질문 패턴을 바탕으로
   주력분야 2개(①부당해고·징계 ②임금체불·퇴직금) 시나리오를 설계하고,
   답변 문구는 근로기준법 등 법령상 일반 기준으로 새로 작성한 오리지널 콘텐츠.
   (특정 사건 자문 아님. 확정 판단은 반드시 공인노무사 상담으로 연결) */
const CONSULT_KNOWLEDGE = `
[부당해고·징계 — 시나리오별 첫 답변 가이드]
■ 근로자 입장
1. 갑작스러운 해고 통보(최다 유형): "해고는 정당한 이유가 있어야 하고, 사유와 시기를 서면으로 통지해야 효력이 있습니다. 구두나 문자로만 통보받으셨다면 그 자체가 다툴 수 있는 지점입니다." → 통보 방식(서면/구두/문자/카톡)과 해고일, 통보받은 날짜부터 확인.
2. 부당해고 구제신청 기간: "노동위원회 구제신청은 해고가 있었던 날부터 3개월 이내에만 가능해서, 지금 시점 확인이 가장 중요합니다." → 해고일이 언제인지, 현재 며칠이 지났는지 확인.
3. 권고사직 압박: "사직서에 서명하시면 스스로 그만둔 것이 되어 부당해고를 다투기 어려워집니다. 서명 전이라면 신중하셔야 하고, 강요 정황은 녹취·메시지로 남겨두시는 것이 좋습니다." → 사직서 제출 여부, 압박 정황 증거(녹취·문자) 유무 확인.
4. 수습·계약직 계약만료: "수습기간이라도 해고에는 정당한 이유가 필요하고, 계약직도 반복 갱신 등으로 갱신기대권이 인정되면 일방적 갱신거절을 다툴 수 있습니다." → 근로계약서 내용, 근무기간, 갱신 이력 확인.
5. 징계(정직·감봉·강등·경고): "징계는 사유의 정당성, 절차의 적법성, 징계 수위의 적정성 세 가지를 모두 갖춰야 하고, 취업규칙상 소명 기회를 안 줬다면 절차 하자를 다툴 수 있습니다." → 징계 사유 통지 내용, 소명(진술) 기회 부여 여부, 취업규칙 확인.
6. 5인 미만 사업장: "상시 근로자 5인 미만 사업장은 부당해고 구제신청 규정이 적용되지 않지만, 해고예고수당이나 퇴직금·임금체불은 별개로 청구할 수 있습니다." → 사업장 상시 근로자 수 확인.
7. 해고예고수당: "30일 전에 예고 없이 해고하면 30일분 이상의 통상임금을 해고예고수당으로 받을 수 있습니다. 다만 3개월 미만 근속 등 예외가 있습니다." → 근속기간, 예고 여부 확인.
8. 구제 인정 시 결과: "부당해고로 인정되면 원직복직과 해고기간 임금 상당액을 받거나, 복직을 원치 않으면 금전보상명령을 신청할 수 있습니다." → 복직 희망 여부 확인.
■ 사업주 입장
9. 문제 직원 해고 검토: "해고가 유효하려면 정당한 이유, 서면통지, 취업규칙상 절차 세 가지를 모두 갖춰야 하고, 하나라도 빠지면 부당해고로 판정될 위험이 큽니다. 징계 사유의 증빙을 먼저 정리하는 것이 순서입니다." → 문제 행위의 구체적 내용과 증빙(경위서·경고장·기록), 취업규칙 유무 확인.
10. 구제신청을 당한 사업주: "노동위원회에서 답변서 제출 요구가 오면 정해진 기한 내 사실관계와 증빙을 정리해 대응해야 하고, 심문회의 전 화해 절차도 선택지가 됩니다." → 신청서 수령일, 해고 경위와 보유 증빙 확인.

[임금체불·퇴직금 — 시나리오별 첫 답변 가이드]
■ 근로자 입장
1. 월급 미지급·지연(최다 유형): "퇴직하셨다면 임금·퇴직금은 퇴직일부터 14일 이내에 지급되어야 하고, 지나면 노동청 진정을 제기할 수 있습니다. 재직 중이라도 임금체불 진정은 가능합니다." → 재직/퇴직 여부, 체불 기간과 대략적 금액 확인.
2. 퇴직금 미지급: "퇴직금은 1년 이상 근속하고 주 15시간 이상 일했다면 발생하고, 퇴직 후 14일이 지나면 연 20%의 지연이자도 붙습니다." → 근속기간, 주당 근로시간, 퇴사일 확인.
3. 연장·야간·휴일수당 미지급: "연장·야간·휴일근로에는 통상임금의 50% 이상을 가산해야 합니다. 다만 5인 미만 사업장은 가산수당 규정이 적용되지 않습니다." → 사업장 규모, 출퇴근 기록(교통카드·메신저·출입기록) 보유 여부 확인.
4. 포괄임금제 다툼: "계약서에 포괄임금이라고 적혀 있어도 실제 연장근로가 약정 시간을 넘으면 차액을 청구할 수 있는 경우가 많습니다." → 계약서의 수당 약정 내용, 실제 근로시간 기록 확인.
5. 사업주 폐업·도산·연락두절: "회사가 도산하거나 지급 능력이 없어도 국가가 대신 지급하는 대지급금(구 체당금) 제도를 이용할 수 있습니다. 노동청 진정으로 체불 사실 확인이 먼저입니다." → 폐업 여부, 4대보험 가입 여부 확인.
6. 연차수당: "사용하지 못한 연차휴가는 수당으로 청구할 수 있고, 회사가 연차사용촉진 절차를 제대로 안 지켰다면 소멸하지 않습니다." → 근속기간, 연차 사용 내역 확인.
7. 최저임금 미달·수습 감액: "최저임금에 미달하는 약정은 그 부분이 무효이고 차액을 청구할 수 있습니다. 수습 감액(10%)도 1년 이상 계약에서 3개월까지만 가능합니다." → 시급 계산 기초(월급·근로시간), 계약서 확인.
8. 소멸시효: "임금채권은 3년이 지나면 청구할 수 없으므로, 체불이 오래됐다면 지금 남은 기간 계산이 급선무입니다." → 체불이 시작된 시점 확인.
9. 근로계약서 없이 일한 경우: "계약서가 없어도 급여이체 내역, 메신저 업무지시, 출퇴근 기록으로 근로 사실을 입증할 수 있습니다. 계약서 미작성 자체도 사업주 처벌 대상입니다." → 급여 수령 방식(계좌/현금), 업무지시 기록 유무 확인.
■ 사업주 입장
10. 체불 진정을 당한 경우: "노동청 출석 조사에서 사실관계를 다투거나, 체불이 맞다면 지급 계획을 정리해 시정하는 것이 형사처벌을 피하는 길입니다. 근로자와 지급 합의(취하 포함)도 조사 단계에서 가능합니다." → 진정 내용(임금/퇴직금/수당), 다툼 지점인지 자금 문제인지 확인.
11. 경영난으로 지급이 어려운 경우: "지급 유예는 근로자 동의를 서면으로 받아야 하고, 일방적 지연은 그대로 체불이 됩니다. 도산 상황이면 대지급금 절차에 협조하는 방법도 안내드릴 수 있습니다." → 체불 규모, 지급 가능 시점 확인.

[그 외 자주 묻는 노무 분야 — 짧은 안내 후 상담 연결]
- 직장 내 괴롭힘: 사용자에게 신고하면 회사는 조사 의무가 있고, 신고를 이유로 한 불리한 처우는 금지·처벌 대상. → 행위의 반복성, 증거(녹취·메시지), 회사 신고 여부 확인.
- 산업재해: 업무상 사고·질병은 근로복지공단에 요양급여를 신청하며, 사업주 날인이 없어도 신청 가능. → 사고 경위, 치료 기록 확인.
- 실업급여: 비자발적 이직 등 수급요건 충족 여부가 핵심이고, 이직확인서 처리가 지연되면 요청할 수 있음. → 이직 사유 코드, 고용보험 가입기간 확인.`;

const VOICE_PROMPT = `너는 노무법인 종로(서울 종로 본사 · 안산지사 · 고양지사)의 김경동 공인노무사를 보조하는 AI 노무 상담원이다.
- 첫 인사는 반드시 다음과 같이 한다: "안녕하세요, 노무법인 종로 김경동 노무사의 AI 상담원입니다. 어떤 일로 상담이 필요하신지 편하게 말씀해 주세요." (자신이 김경동 노무사 본인인 것처럼 말하지 않는다)
- 상담자를 부를 때는 반드시 '의뢰인님'이라고 호칭한다. '고객님', '선생님' 등 다른 호칭은 쓰지 않는다.
- 한 번에 하나씩, 공감적으로 짧게(1~2문장) 질문한다.
- 상담유형(부당해고·징계/임금체불·퇴직금/직장 내 괴롭힘/산업재해/실업급여 등)과 '보유 증빙'(근로계약서·급여명세·메시지·녹취·출퇴근 기록 등)을 반드시 확인한다.
- 상담 흐름은 2단계다: ①의뢰인님의 상황이 파악되면 [지식]의 해당 시나리오로 일반 기준을 먼저 안내(1차 답변) → ②이어서 판정·입증에서 중요한 자료(계약서, 통지서, 기록, 기간, 일정 등)를 보유하고 있는지 시나리오의 확인 질문 순서대로 하나씩 묻는다.
- 부당해고·징계 또는 임금체불·퇴직금 상담으로 파악되면, 아래 [지식]의 해당 항목을 활용해 첫 답변에서 일반적인 기준을 한두 문장으로 먼저 안내한 뒤, '확인' 순서대로 하나씩 질문한다.
- 기간이 결과를 좌우하는 사안(구제신청 3개월, 임금채권 소멸시효 3년, 금품청산 14일)은 날짜를 반드시 짚어서 확인한다.
- 지식에 없는 세부 수치나 판례를 임의로 만들어 말하지 않는다.
- 확정적 판정 예측이나 결과 보장은 하지 않는다. 일반적인 기준만 안내하고 "정확한 판단은 김경동 노무사 상담(02-6929-4540)에서 가능하다"고 연결한다.
- 중국어 상담을 원하는 의뢰인에게는 "김경동 노무사가 중국어 상담이 가능하니 02-6929-4540으로 연락 주시면 직접 도와드린다"고 안내한다.
- 위협·자해 등 위급 신호가 보이면 즉시 전문기관 연락을 안내한다.

[차례 지키기] 의뢰인님이 말하는 도중 잠시 멈추거나 더듬어도(음…, 어…, 그…, 짧은 침묵) 절대 끼어들지 마라. 의뢰인님이 한 문장을 분명히 끝맺은 뒤에만 응답한다. 아직 생각 중인 것 같으면 한두 박자 더 기다린다.
[발화 길이] 한 번에 2~4문장으로 짧게 말한 뒤 즉시 멈추고, 의뢰인님이 실제로 말할 때까지 기다린다. 절대 혼자 묻고 스스로 답하며 대화를 이어가지 마라.
[소음 무시] 들리는 소리가 말이 아닌 소음이거나 내용이 불분명하면 절대 새로운 주제(해고 등)를 꺼내지 말고, 조용히 기다리거나 "죄송합니다, 잘 못 들었어요. 다시 한번 말씀해 주시겠어요?"라고만 짧게 되묻는다. 의뢰인님이 언급하지 않은 상담 유형을 먼저 가정하지 마라.
[말투·속도] 실제 사람처럼 자연스러운 구어체로 말한다. 너무 빠르지 않게 편안한 속도로, 한 번에 길게 늘어놓지 말고 짧게 주고받는다.
[언어] 모든 발화는 한국어로만 한다. 어떤 경우에도 다른 언어로 바꾸지 않는다. (중국어 상담 요청 시에는 위 안내대로 노무사 전화 상담으로 연결한다)
[숫자 확인] 체불 금액·근속기간·해고일 같은 결과를 좌우하는 숫자와 날짜는 애매하게 들리면 절대 임의로 해석하지 말고 반드시 되물어 확인한다. 예: "3개월이라고 하셨는데, 해고된 지 3개월이 지났다는 말씀인지, 근무기간이 3개월이라는 말씀인지 확인 부탁드립니다." 확인 전에는 그 숫자를 전제로 판단하지 않는다.
위에 정한 첫 인사로 시작하고, 이후 의뢰인님의 문의사항을 파악하라.

[지식]
${CONSULT_KNOWLEDGE}`;

/* 관점(근로자/사업주)별 추가 지침 — /api/realtime/token 및 /api/voice-chat 에서 주입 */
function perspectiveNote(persp) {
  if (persp === '노동자') return `\n\n[의뢰인 관점] 의뢰인님은 '근로자' 입장이다. 근로자의 권리 구제(구제신청, 진정, 수당·퇴직금 청구, 증거 확보) 관점에서 안내하고, 회사에 불리한 자충수(사직서 서명, 합의서 검토 없는 날인 등)를 주의시켜라. 사례 검색 시에도 근로자 관점 결과를 전제로 답하라.`;
  if (persp === '사업주') return `\n\n[의뢰인 관점] 의뢰인님은 '사업주' 입장이다. 법 위반 리스크 예방과 적법한 절차(서면통지, 취업규칙 절차, 지급 계획, 노동청 조사 대응) 관점에서 안내하고, 근로자와의 분쟁을 키우지 않는 실무적 해법을 함께 제시하라. 사례 검색 시에도 사업주 관점 결과를 전제로 답하라.`;
  return '';
}

/* ============================================================
   1) Realtime 음성 — ephemeral client secret 발급
      GA 엔드포인트: POST /v1/realtime/client_secrets
      반환된 value(ek_...)를 브라우저가 WebRTC 인증에 사용
   ============================================================ */
app.get('/api/realtime/token', ipLimit('rt', 6), pwGate, turnstileGate, dailyCap('realtime'), async (req, res) => {
  try {
    // ?model=mini → gpt-realtime-mini (비용 절감형 실시간), 기본은 gpt-realtime
    const rtModel = req.query.model === 'mini' ? 'gpt-realtime-mini' : 'gpt-realtime';
    // ?perspective=노동자|사업주 — 관점 선택 게이트에서 전달 (없으면 지침 미주입)
    const persp = ['노동자', '사업주'].includes(req.query.perspective) ? req.query.perspective : '';
    const r = await fetch('https://api.openai.com/v1/realtime/client_secrets', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${OPENAI_KEY}`,
        // 안정적 사용자 식별자(선택) — ephemeral 발급 시점에 서버에서 바인딩
        'OpenAI-Safety-Identifier': req.ip || 'web-visitor',
      },
      body: JSON.stringify({
        session: {
          type: 'realtime',
          model: rtModel,            // 요청하신 리얼타임미니
          output_modalities: ['audio'],
          audio: {
            input: {
              format: { type: 'audio/pcm', rate: 24000 },
              // 소음·에코 오인 방지: 임계값 기반 감지 + 잡음 억제 (2026-07-09 폰트 테스트 반영)
              // 모바일 스피커폰 기준: 또렷한 발화만 인식, 문장 끝맺음까지 충분히 대기,
              // AI가 말하는 동안 소음으로 끊기지 않도록 interrupt 비활성 (2026-07-09)
              turn_detection: { type: 'server_vad', threshold: 0.85, prefix_padding_ms: 300,
                                silence_duration_ms: 900, create_response: true, interrupt_response: false },
              noise_reduction: { type: 'near_field' },
              transcription: { model: 'gpt-4o-mini-transcribe', language: 'ko' }, // 한국어 고정 — 'ああ' 등 외국어 환청 방지
            },
            output: {
              format: { type: 'audio/pcm', rate: 24000 },
              voice: 'cedar',                    // 남성 음성 (대안: ash, echo)
              speed: 0.85,                       // 말 속도 (1=기본, 낮을수록 천천히)
            },
          },
          instructions: VOICE_PROMPT + perspectiveNote(persp) + `\n\n[상담 시간] 1회 상담은 최대 40분이다. 시스템이 남은 시간을 알려주면 반드시 그 안내에 따라 마무리를 진행하고, 시간 안내 이후에는 새 주제를 확장하지 마라.

[검색 도구 사용법] 너에게 두 가지 검색 도구가 있다.
1) search_cases — 실제 상담사례 검색. 2) search_precedents — 실제 법원 판례 검색.
사용 순서(중요): 먼저 의뢰인의 정황을 1~2개의 짧은 질문으로 파악하라(언제·수치·상대방 대응 등 핵심만). 상황이 어느 정도 구체화되면 search_cases로 유사 상담사례를 검색해 근거 있는 답을 하고, 의뢰인이 판례나 재판 결과를 궁금해하거나 사안이 다툼의 소지가 있으면 search_precedents로 실제 판례를 찾아 "이런 판례들이 있다"고 알려줘라. 첫 인사나 잡담에는 검색하지 마라.
검색 결과의 원문을 그대로 읽지 말고 반드시 너의 말로 자연스럽게 재구성하라. 판례는 검색 결과에 있는 사건번호·법원·선고일만 언급하고 내용은 절대 지어내지 마라. 검색하는 동안에는 "네, 비슷한 사례를 잠시 찾아볼게요" 같은 짧은 말로 자연스럽게 이어가라.`,
          tools: [{
            type: 'function',
            name: 'search_cases',
            description: '실제 노무 상담사례 데이터베이스(19,718건: 노동자 14,913 / 사업주 4,805)에서 의뢰인 상황과 유사한 사례를 검색한다. 부당해고, 징계, 임금체불, 퇴직금, 수당, 직장 내 괴롭힘, 산재, 실업급여 등 모든 노무 질문에 사용.',
            parameters: {
              type: 'object',
              properties: {
                query: { type: 'string', description: '의뢰인 상황을 요약한 검색 질문 (한국어, 예: "권고사직 거부 후 해고 통보 구제신청")' },
              },
              required: ['query'],
            },
          }, {
            type: 'function',
            name: 'search_precedents',
            description: '국가법령정보센터에서 실제 법원 판례를 검색한다. 의뢰인이 판례·판정례·법원 판단을 궁금해할 때 사용. 결과는 사건번호·법원·선고일 목록.',
            parameters: {
              type: 'object',
              properties: {
                query: { type: 'string', description: '판례 검색 키워드 (짧게, 노동사건 중심 예: "부당해고 서면통지", "퇴직금 지연이자", "통상임금")' },
              },
              required: ['query'],
            },
          }],
          tool_choice: 'auto',
        },
      }),
    });
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);   // 클라이언트는 data.value 사용
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: '토큰 발급 실패', detail: String(e) });
  }
});

/* ============================================================
   2) 상담 종료 → 대화 요약 → 변호사 메일 전송
      body: { type, transcript:[{who,text}], durationSec }
   ============================================================ */
app.post('/api/consult/finish', ipLimit('fin', 5), turnstileGate, dailyCap('finish'), async (req, res) => {
  try {
    const { type = '노무상담', transcript = [], durationSec = 0 } = req.body;
    const persp = ['노동자', '사업주'].includes(req.body?.perspective) ? req.body.perspective : '';
    const convo = transcript.map(t => `${t.who === 'ai' ? '상담원' : '상담자'}: ${t.text}`).join('\n');

    // (a) LLM으로 변호사 전달용 구조화 요약 생성
    let summary = { 사건유형: type, 핵심사실: '', 보유증빙: '', 쟁점: '', 권장지참자료: '' };
    try {
      const r = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${OPENAI_KEY}` },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: '아래 노무 상담 대화를 공인노무사 전달용으로 요약해 JSON으로만 답하라. 키: 사건유형, 핵심사실, 보유증빙, 쟁점, 권장지참자료. 확정적 판단은 하지 말 것.' },
            { role: 'user', content: convo },
          ],
        }),
      });
      const j = await r.json();
      summary = JSON.parse(j.choices?.[0]?.message?.content || '{}');
    } catch (e) { console.warn('요약 실패, 원문 전송', e); }

    // (b) 메일 발송
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST, port: 465, secure: true,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000, // 무한대기 방지: 10초 내 실패 확정
    });
    const row = (k, v) => `<tr><td style="padding:6px 12px;color:#777;white-space:nowrap">${k}</td><td style="padding:6px 12px">${v || '-'}</td></tr>`;
    await transporter.sendMail({
      from: `"노무법인 종로 AI 음성상담" <${process.env.SMTP_USER}>`,
      to: process.env.LAWYER_EMAIL,
      subject: `[상담요청${persp ? '·' + persp : ''}] ${summary.사건유형 || type} — AI 음성 사전상담`,
      html: `
        <h2>AI 음성 사전상담 요약</h2>
        <p style="color:#888">상담시간 약 ${Math.round(durationSec/60)}분 · 자동 생성</p>
        <table style="border-collapse:collapse;border:1px solid #eee">
          ${row('의뢰인 관점', persp || '(미선택)')}
          ${row('사건유형', summary.사건유형)}
          ${row('핵심사실', summary.핵심사실)}
          ${row('보유증빙', summary.보유증빙)}
          ${row('쟁점', summary.쟁점)}
          ${row('권장지참자료', summary.권장지참자료)}
        </table>
        <details style="margin-top:16px"><summary>전체 대화 기록</summary>
          <pre style="white-space:pre-wrap;font-size:13px;color:#333">${convo}</pre>
        </details>
        <hr><small>본 요약은 AI가 자동 생성했으며 참고용입니다. 확정적 판단이 아닙니다.</small>`,
    });
    res.json({ ok: true, summary });
  } catch (e) {
    console.error(e);
    res.status(502).json({ ok: false, error: '전송 실패', detail: String(e) });
  }
});

/* ============================================================
   3) 판례 목록 프록시 (CORS 우회 + 인증키 보호)
      GET /api/precedents?type=dui&q=음주운전&curt=수원지방법원
   ============================================================ */
const TYPE_QUERY = {
  dismissal:  { query: '부당해고',        JO: '근로기준법' },
  discipline: { query: '징계 해고',       JO: '근로기준법' },
  wage:       { query: '임금 체불',       JO: '근로기준법' },
  severance:  { query: '퇴직금',          JO: '근로자퇴직급여 보장법' },
  harassment: { query: '직장 내 괴롭힘',   JO: '근로기준법' },
  industrial: { query: '업무상 재해',      JO: '산업재해보상보험법' },
};
async function searchPrecedents({ type, q, curt, prncYd, display = '10', page = '1' } = {}) {
  const t = TYPE_QUERY[type] || {};
  // ※ 검증된 호출 형식 유지: OC/target/type/query/display/page 만 사용.
  //   (JO·search 파라미터를 추가하면 결과가 0건으로 나오는 것을 확인함 — 2026-07-09)
  const params = new URLSearchParams({
    OC: LAW_OC, target: 'prec', type: 'JSON',
    query: q || t.query || '', display: String(display), page: String(page),
  });
  if (curt) params.set('curt', curt);
  if (prncYd) params.set('prncYd', prncYd);
  const r = await fetch(`https://www.law.go.kr/DRF/lawSearch.do?${params}`);
  const data = await r.json();
  const raw = data?.PrecSearch?.prec;
  const arr = Array.isArray(raw) ? raw : raw ? [raw] : [];   // 결과 1건이면 객체로 오는 경우 대응
  return {
    count: data?.PrecSearch?.totalCnt ?? arr.length,
    items: arr.map(p => ({
      id: p['판례일련번호'], case: p['사건명'], caseNo: p['사건번호'],
      court: p['법원명'], date: p['선고일자'], type: p['사건종류명'],
      verdict: p['판결유형'],
      link: `/api/precedents/${p['판례일련번호']}/html`,   // OC 노출 방지: 자체 프록시 경유
    })),
  };
}

app.get('/api/precedents', async (req, res) => {
  try {
    res.json(await searchPrecedents(req.query));
  } catch (e) {
    res.status(502).json({ error: '판례 조회 실패', detail: String(e) });
  }
});

/* 판례 본문(HTML) 프록시 — 인증키를 서버에만 두고 상세 페이지 제공 */
app.get('/api/precedents/:id/html', async (req, res) => {
  try {
    const id = String(req.params.id).replace(/[^0-9]/g, '');
    const r = await fetch(`https://www.law.go.kr/DRF/lawService.do?OC=${LAW_OC}&target=prec&type=HTML&ID=${id}`);
    const html = await r.text();
    res.set('Content-Type', 'text/html; charset=utf-8').send(html);
  } catch (e) {
    res.status(502).send('판례 본문을 불러오지 못했습니다.');
  }
});

/* ============================================================
   4) 승소가능성(참고 지표) 계산 — 밴드/범위 + 근거 판례
   ============================================================ */
const WEIGHTS = {
  dismissal: { base: 50, factors: {
    written:  { yes: -10, no: 14 },            // 서면통지 여부 (근로자 관점: 서면 없으면 다툼 유리)
    reason:   { weak: 12, disputed: 4, strong: -10 },
    procedure:{ violated: 10, ok: -4, unknown: 0 },
    size:     { over5: 6, under5: -14 },
    period:   { within3m: 8, over3m: -20 },
  }},
  // wage / harassment / industrial … 동일 패턴으로 추가
};
app.post('/api/win-estimate', async (req, res) => {
  const { type, answers } = req.body;
  const cfg = WEIGHTS[type];
  if (!cfg) return res.status(400).json({ error: '지원하지 않는 사건유형' });
  let score = cfg.base; const factors = [];
  for (const [k, v] of Object.entries(answers || {})) {
    const w = cfg.factors[k]?.[v] ?? 0; score += w;
    factors.push({ key: k, value: v, weight: w, kind: w >= 0 ? 'fav' : 'unf' });
  }
  score = Math.max(8, Math.min(92, score));
  const band = score >= 68 ? '높음' : score >= 45 ? '보통' : '낮음';
  let precedents = [];
  try { precedents = (await searchPrecedents({ type, display: 3 })).items || []; } catch {}
  res.json({
    score, range: [Math.max(5, score - 9), Math.min(95, score + 9)], band, factors, precedents,
    disclaimer: '참고용 예측이며 실제 결과를 보장하지 않습니다. 반드시 변호사 상담이 필요합니다.',
  });
});

/* ============================================================
   4.5) 절약형 음성상담 — STT(전사) → GPT-4o mini(답변) → TTS(음성)
        리얼타임 대비 비용 약 1/10. 꾹 누르고 말하기(PTT) 방식과 짝을 이룸.
        POST /api/voice-chat  { audioB64?, mime?, history[], greet? }
   ============================================================ */
const ECO_CHAT_MODEL = 'gpt-4o';             // 절약형 답변 모델 (더 절약하려면 'gpt-4o-mini')
const ECO_TTS_VOICE = 'onyx';                // 남성 음성
const GREETING = '안녕하세요, 노무법인 종로 김경동 노무사의 AI 상담원입니다. 어떤 일로 상담이 필요하신지 편하게 말씀해 주세요.';

app.post('/api/voice-chat', ipLimit('vc', 150), turnstileGate, dailyCap('voicechat'), async (req, res) => {
  try {
    const { audioB64, mime, history = [], greet } = req.body || {};
    const persp = ['노동자', '사업주'].includes(req.body?.perspective) ? req.body.perspective : '';
    let userText = '';

    if (!greet) {
      if (!audioB64) return res.status(400).json({ error: '오디오가 없습니다.' });
      // 1) 음성 → 텍스트 (전사)
      const buf = Buffer.from(audioB64, 'base64');
      const fd = new FormData();
      fd.append('file', new Blob([buf], { type: mime || 'audio/webm' }), 'speech.webm');
      fd.append('model', 'gpt-4o-mini-transcribe');
      fd.append('language', 'ko');
      fd.append('prompt', '한국어 노무 상담 통화입니다. 부당해고, 징계, 임금체불, 퇴직금, 수당, 직장 내 괴롭힘, 산재 관련 대화이며 체불 금액이나 근속기간, 날짜 같은 숫자가 나올 수 있습니다.');
      const tr = await fetch('https://api.openai.com/v1/audio/transcriptions', {
        method: 'POST', headers: { Authorization: `Bearer ${OPENAI_KEY}` }, body: fd,
      });
      const trData = await tr.json();
      if (!tr.ok) throw new Error('전사 실패: ' + JSON.stringify(trData));
      userText = (trData.text || '').trim();
      // 외국어 환청 필터: 한글도 숫자도 없는 결과는 소음으로 간주하고 조용히 무시
      const hasKo = /[가-힣]/.test(userText), hasNum = /[0-9]/.test(userText);
      if (userText.length < 2 || (!hasKo && !hasNum)) {
        return res.json({ userText: '', aiText: '', audioB64: null, empty: true });
      }
    }

    // 2) 답변 생성 (동일한 상담 지식·규칙 사용)
    let aiText = GREETING;
    if (!greet) {
      // [RAG] 실제 상담사례 검색 → 근거 주입 (Upstash 미설정·검색 실패 시 조용히 건너뜀)
      let ragContext = '';
      if (UPSTASH_URL && UPSTASH_TOKEN) {
        try {
          // 판례 관심 감지: 판례·판결·형량 등 언급 시 실제 판례도 병렬 검색 (지연 최소화)
          const wantsPrec = /판례|판결|판정|재판|법원|노동위원회|선고|승소|패소/.test(userText);
          const [found, prec] = await Promise.all([
            ragSearch(userText, 3, RAG_NAMESPACE, persp).then(r => r.filter(c => c.score >= 0.35)).catch(() => []),
            wantsPrec ? searchPrecedents({ q: userText.slice(0, 60), display: '3' }).catch(() => ({ items: [] })) : Promise.resolve({ items: [] }),
          ]);
          if (found.length) {
            ragContext += '\n\n[실제 상담사례 — 답변의 근거로 활용하되 원문을 그대로 읽지 말고 너의 말로 재구성할 것]\n'
              + found.map((c, i) => `사례${i + 1}(${c.type}): ${c.answer.slice(0, 700)}`).join('\n');
          }
          if (prec.items && prec.items.length) {
            ragContext += '\n\n[실제 법원 판례 목록 — 아래 사건번호·법원·선고일만 사실이며 판결 내용은 포함되지 않았다. 내용을 절대 지어내지 말고 "이런 판례들이 있다" 수준으로만 언급하고 자세한 분석은 변호사 상담으로 연결할 것]\n'
              + prec.items.map(p => `- ${p.court} ${p.caseNo} (${p.date} 선고) ${p.case}`).join('\n');
          }
        } catch (e) { console.error('[voice-chat RAG]', e.message); }
      }
      const msgs = [
        { role: 'system', content: VOICE_PROMPT + perspectiveNote(persp) + ragContext + '\n[중요] 음성으로 읽힐 답변이다. 특수문자·목록 없이 자연스러운 구어체 2~4문장으로만 답하라.' },
        ...history.slice(-16).map(h => ({ role: h.who === 'user' ? 'user' : 'assistant', content: String(h.text || '').slice(0, 1000) })),
        { role: 'user', content: userText },
      ];
      const cc = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${OPENAI_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: ECO_CHAT_MODEL, messages: msgs, max_tokens: 300, temperature: 0.6 }),
      });
      const ccData = await cc.json();
      if (!cc.ok) throw new Error('답변 생성 실패: ' + JSON.stringify(ccData));
      aiText = (ccData.choices?.[0]?.message?.content || '').trim();
    }

    // 3) 텍스트 → 음성: 문장별로 쪼개 병렬 합성 → 대기시간이 '문단 전체'가 아닌 '문장 하나' 수준으로 단축
    const ttsOne = async (text) => {
      const t = await fetch('https://api.openai.com/v1/audio/speech', {
        method: 'POST',
        headers: { Authorization: `Bearer ${OPENAI_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'gpt-4o-mini-tts', voice: ECO_TTS_VOICE, input: text, response_format: 'mp3',
          instructions: '차분하고 신뢰감 있는 한국어 남성 노무 상담원 톤으로, 너무 빠르지 않게.' }),
      });
      if (!t.ok) throw new Error('음성 합성 실패: ' + (await t.text()));
      return Buffer.from(await t.arrayBuffer()).toString('base64');
    };
    let sents = (aiText.match(/[^.!?…]+[.!?…]*/g) || [aiText]).map(s => s.trim()).filter(s => s.length > 1);
    // 너무 잘게 쪼개지 않도록 2문장씩 묶음 (합성 호출 수 절감)
    const groups = [];
    for (let i = 0; i < sents.length; i += 2) groups.push(sents.slice(i, i + 2).join(' '));
    const audioSegs = await Promise.all(groups.map(ttsOne));

    res.json({ userText, aiText, audioSegs, audioB64: audioSegs[0] });
  } catch (e) {
    console.error('절약형 상담 오류:', e);
    res.status(502).json({ error: '음성 상담 처리 실패', detail: String(e).slice(0, 300) });
  }
});

/* ============================================================
   5) 유튜브 최신 영상 — 환경변수(YT_CHANNEL_HANDLE/ID) 설정 시에만 활성 (프록시)
      GET /api/youtube/latest?limit=16
      영상 ID: 채널 페이지에서 추출(안정적) / 제목: 공식 oEmbed 조회
      RSS 폴백(최대 15개) · 10분 메모리 캐시
   ============================================================ */
const YT_CHANNEL_HANDLE = process.env.YT_CHANNEL_HANDLE || '';   // 노무법인 종로 유튜브 개설 시 환경변수로 등록
const YT_CHANNEL_ID = process.env.YT_CHANNEL_ID || '';
let ytCache = { at: 0, items: [] };

app.get('/api/youtube/latest', async (req, res) => {
  if (!YT_CHANNEL_HANDLE && !YT_CHANNEL_ID) return res.status(404).json({ error: '유튜브 채널 미설정' });
  const limit = Math.min(parseInt(req.query.limit) || 16, 30);
  if (Date.now() - ytCache.at < 10 * 60 * 1000 && ytCache.items.length) {
    return res.json({ count: Math.min(limit, ytCache.items.length), items: ytCache.items.slice(0, limit), cached: true });
  }
  const dedupe = (arr) => { const s = new Set(); return arr.filter(v => !s.has(v.id) && s.add(v.id)); };
  try {
    // 1) 채널 페이지에서 영상 ID 추출
    const r = await fetch(`https://www.youtube.com/@${YT_CHANNEL_HANDLE}/videos`, {
      headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'accept-language': 'ko' },
    });
    const html = await r.text();
    const ids = [];
    const seen = new Set();
    for (const mm of html.matchAll(/"videoId":"([\w-]{11})"/g)) {
      if (!seen.has(mm[1])) { seen.add(mm[1]); ids.push(mm[1]); }
      if (ids.length >= limit) break;
    }
    if (!ids.length) throw new Error('영상 ID 추출 실패');
    // 2) 제목은 유튜브 공식 oEmbed로 조회 — 페이지 구조 변경에 영향받지 않음
    const items = (await Promise.all(ids.map(async (id) => {
      try {
        const rr = await fetch(`https://www.youtube.com/oembed?url=https%3A%2F%2Fyoutu.be%2F${id}&format=json`);
        if (!rr.ok) return null;
        const j = await rr.json();
        return { id, title: j.title || '' };
      } catch { return null; }
    }))).filter(v => v && v.title);
    if (!items.length) throw new Error('제목 조회 실패');
    ytCache = { at: Date.now(), items };
    res.json({ count: Math.min(limit, items.length), items: items.slice(0, limit) });
  } catch (e) {
    // 2차: RSS 폴백 (최대 15개)
    try {
      const r = await fetch(`https://www.youtube.com/feeds/videos.xml?channel_id=${YT_CHANNEL_ID}`);
      const xml = await r.text();
      const items = dedupe([...xml.matchAll(/<yt:videoId>([\w-]{11})<\/yt:videoId>[\s\S]*?<title>([^<]+)<\/title>/g)]
        .map(m => ({ id: m[1], title: m[2] }))).slice(0, limit);
      if (!items.length) throw new Error('RSS 파싱 실패');
      ytCache = { at: Date.now(), items };
      res.json({ count: items.length, items });
    } catch (e2) {
      console.error('유튜브 조회 실패:', e, e2);
      res.status(502).json({ error: '유튜브 영상 조회 실패', detail: String(e2) });
    }
  }
});

/* ============================================================
   [RAG] 실제 상담사례 기반 챗봇 — Upstash Vector 검색 + GPT 근거 답변
   활성 조건: 클라우드타입 환경변수 UPSTASH_VECTOR_URL / UPSTASH_VECTOR_TOKEN
   (읽기전용 토큰 권장). 없으면 이 기능만 조용히 꺼져 있음.
   ============================================================ */
const UPSTASH_URL = process.env.UPSTASH_VECTOR_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_VECTOR_TOKEN;
const RAG_NAMESPACE = process.env.RAG_NAMESPACE || 'nomusa';

async function ragSearch(question, topK = 4, namespace = RAG_NAMESPACE, perspective = '') {
  // 1) 질문 임베딩 (적재 때와 동일: text-embedding-3-small 512차원)
  const er = await fetch('https://api.openai.com/v1/embeddings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ model: 'text-embedding-3-small', input: question.slice(0, 2000), dimensions: 512 }),
  });
  if (!er.ok) throw new Error('embed ' + er.status);
  const vector = (await er.json()).data[0].embedding;
  // 2) Upstash 유사도 검색
  const body = { vector, topK, includeMetadata: true };
  if (perspective) body.filter = `perspective = '${perspective}'`;
  const qr = await fetch(`${UPSTASH_URL}/query/${namespace}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${UPSTASH_TOKEN}` },
    body: JSON.stringify(body),
  });
  if (!qr.ok) throw new Error('vector ' + qr.status);
  const j = await qr.json();
  return (j.result || []).map(m => ({ score: m.score, ...m.metadata }));
}

// 리얼타임 음성상담의 search_cases 도구가 사용하는 경량 검색 엔드포인트
app.post('/api/rag-search', ipLimit('rs', 200), async (req, res) => {
  try {
    if (!UPSTASH_URL || !UPSTASH_TOKEN) return res.json({ result: '사례 데이터베이스가 아직 준비되지 않았습니다.' });
    const q = String(req.body?.query || '').trim().slice(0, 500);
    if (!q) return res.json({ result: '검색어가 없습니다.' });
    const ns = RAG_NAMESPACE;   // 이 사이트는 nomusa 고정
    const persp = ['노동자', '사업주'].includes(req.body?.perspective) ? req.body.perspective : '';
    const found = (await ragSearch(q, 3, ns, persp)).filter(c => c.score >= 0.35);
    if (!found.length) return res.json({ result: '유사한 상담사례를 찾지 못했습니다. 일반 기준으로 안내하고 공인노무사 상담을 권하세요.' });
    const result = found.map((c, i) => `사례${i + 1}(${c.type}): ${c.answer.slice(0, 600)}`).join('\n');
    res.json({ result });
  } catch (e) {
    console.error('[/api/rag-search]', e.message);
    res.json({ result: '검색 중 오류가 발생했습니다. 일반 기준으로 안내하세요.' });
  }
});

// 리얼타임 음성상담의 search_precedents 도구용 — 실제 법원 판례 목록 브리핑
app.post('/api/precedent-brief', ipLimit('pb', 200), async (req, res) => {
  try {
    const q = String(req.body?.query || '').trim().slice(0, 200);
    if (!q) return res.json({ result: '검색어가 없습니다.' });
    const { count, items } = await searchPrecedents({ q, display: '3' });
    if (!items.length) return res.json({ result: '관련 판례가 검색되지 않았습니다. 판례 언급 없이 일반 기준으로 안내하세요.' });
    const list = items.map(p => `- ${p.court} ${p.caseNo} (${p.date} 선고) ${p.case}`).join('\n');
    res.json({ result: `실제 판례 ${count}건 중 상위 목록:\n${list}\n[주의] 위는 판례의 제목·법원·선고일 정보만이다. 판결의 구체적 내용은 포함되지 않았으니 절대 내용을 지어내지 말고, "이런 판례들이 있다" 수준으로만 언급하며 자세한 분석은 변호사 상담으로 연결하라.` });
  } catch (e) {
    console.error('[/api/precedent-brief]', e.message);
    res.json({ result: '판례 검색 중 오류. 판례 언급 없이 일반 기준으로 안내하세요.' });
  }
});

app.post('/api/chat', ipLimit('chat', 60), turnstileGate, dailyCap('chat'), async (req, res) => {
  try {
    if (!UPSTASH_URL || !UPSTASH_TOKEN) {
      return res.status(503).json({ error: '상담사례 검색 기능 준비 중입니다.' });
    }
    const question = String(req.body?.question || '').trim();
    if (!question || question.length > 1500) {
      return res.status(400).json({ error: '질문을 1~1500자로 입력해주세요.' });
    }
    // 네임스페이스: 이 사이트는 노무 상담 전용 — nomusa 고정
    const ns = 'nomusa';
    // 관점 필터: 노동자 | 사업주
    const persp = ['노동자', '사업주'].includes(req.body?.perspective) ? req.body.perspective : '';
    const cases = await ragSearch(question, 4, ns, persp);
    const usable = cases.filter(c => c.score >= 0.35); // 관련성 낮으면 근거로 안 씀
    const context = usable.map((c, i) =>
      `[사례${i + 1}] (분야: ${c.type})\n질문: ${c.question}\n답변 요지: ${c.answer}`).join('\n\n');

    const sysNomusa = `너는 노무법인 종로(김경동 공인노무사)의 노무 상담 AI다. 아래 [실제 상담사례]만을 근거로 답변하라. 규칙:
1) 사례에 없는 내용은 지어내지 말고 "해당 사안은 상담사례에서 확인되지 않아, 공인노무사 상담이 필요합니다"라고 답할 것.
2) 사례 원문을 그대로 복사하지 말고 반드시 너의 문장으로 재구성할 것.
3) 결과 보장 금지. 일반적 법리와 기준만 안내.${persp ? ` 질문자는 ${persp} 입장이다.` : ''}
4) 답변 끝에 "정확한 판단은 노무법인 종로 김경동 노무사 상담(02-6929-4540)으로 확인하세요."를 포함.
5) 답변은 400자 이내, 존댓말.`;
    const sys = sysNomusa;

    const gr = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${OPENAI_KEY}` },
      body: JSON.stringify({
        model: 'gpt-4o-mini', temperature: 0.3, max_tokens: 700,
        messages: [
          { role: 'system', content: sys },
          { role: 'user', content: (context ? `[실제 상담사례]\n${context}\n\n` : '[실제 상담사례]\n(관련 사례 없음)\n\n') + `[의뢰인 질문]\n${question}` },
        ],
      }),
    });
    if (!gr.ok) throw new Error('gpt ' + gr.status);
    const answer = (await gr.json()).choices?.[0]?.message?.content || '';
    res.json({
      answer,
      sources: usable.map(c => ({ type: c.type, question: c.question, url: c.url })),
    });
  } catch (e) {
    console.error('[/api/chat]', e.message);
    res.status(500).json({ error: '답변 생성 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.' });
  }
});

const PORT = process.env.PORT || 3000;
// Vercel(서버리스)에서는 플랫폼이 요청을 전달하므로 직접 listen하지 않음. 로컬/일반 서버에서만 listen.
if (!process.env.VERCEL) {
  app.listen(PORT, () => console.log(`▶ server on http://localhost:${PORT}`));
}
export default app;
