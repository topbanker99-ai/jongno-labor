# 노무법인 종로 — AI 음성 노무상담 홈페이지

김경동 공인노무사(노무법인 종로) 홈페이지. 검증된 운영 코드(Express + OpenAI Realtime + Upstash Vector RAG)를 노무 상담 특화로 개조한 버전입니다.

- 본사 (03191) 서울시 종로구 종로96, 한올타워 6층
- 안산지사 (15471) 경기도 안산시 단원구 광덕대로 161, 501-1호
- 고양지사 (10564) 경기도 고양시 덕양구 원흥3로 16, 904호
- DL 02-6929-4540 · M 010-5028-9299 · F 02-6919-4056 · E kkd@jnhrm.co.kr

---

## 1. 구성

```
server.js            Express 서버 (API 전부)
public/index.html    프론트 전체 (단일 파일)
public/img/          seal.png(인장) · favicon.png · og-card.png
deploy-main.yml      클라우드타입 자동배포 (→ .github/workflows/ 로 이동)
package.json
```

## 2. 핵심 기능

### AI 음성 상담 (전체화면 오버레이)
- 진입: 우하단 플로팅 버튼, 상단 CTA, 또는 **주소 뒤에 `#consult`** 직링크 (카톡·QR 배포용)
- **STEP 1 — 관점 선택 게이트(필수)**: [근로자입니다 / 사업주입니다]. 기본값 없음, 선택 전에는 상담 시작 불가.
- **STEP 2 — 상담**: 3가지 모드
  - 리얼타임 (`gpt-realtime`) / 리얼타임 미니 (`gpt-realtime-mini`) — WebRTC
  - 절약형 (STT → GPT-4o → TTS) — 자동 음성감지, 비용 약 1/10
- 1회 40분 제한 (35분 마무리 안내 → 39분 종료 인사 → 40분 자동 종료)
- 종료 시 대화 요약을 `LAWYER_EMAIL`(kkd@jnhrm.co.kr)로 자동 발송. 메일에 **의뢰인 관점** 표기.

### 관점(perspective)이 흐르는 지점
선택한 값(`노동자` / `사업주`)은 아래 5곳에 전부 전달됩니다.

| 위치 | 효과 |
|---|---|
| `/api/realtime/token?perspective=` | AI 지침에 관점별 안내 방향 주입 |
| `/api/rag-search` | Upstash `metadata.perspective` 필터 |
| `/api/voice-chat` (인사·대화) | 시스템 프롬프트 + RAG 필터 |
| `/api/consult/finish` | 메일 제목·본문에 관점 표기 |

### RAG
- Upstash Vector 인덱스, 네임스페이스 **`nomusa`** (노무 상담 19,718건 / 노동자 14,913 · 사업주 4,805)
- 임베딩: `text-embedding-3-small`, 512차원, COSINE
- 원문 재현 금지 — AI가 반드시 자기 문장으로 재구성하도록 지침화

### 사전진단 (#calc)
부당해고·징계 / 임금체불·퇴직금 / 직장 내 괴롭힘 / 산업재해 4종. **근로자 관점 기준**.
판단 근거는 **법령 조문**(근로기준법 23·27·28·36·49·76의2조, 퇴직급여법 9조, 산재법 37·41조)만 표기하며 **사건번호·판례를 창작하지 않습니다.**

---

## 3. 배포 (클라우드타입 + 깃허브 Actions)

### ① 깃허브
새 저장소(예: `jongno-labor`) 생성 후 이 폴더 내용을 push.
`deploy-main.yml`은 **`.github/workflows/deploy-main.yml`** 경로에 두어야 작동합니다.

### ② 클라우드타입
프로젝트를 생성합니다. 프로젝트명을 `jongno-labor`가 아닌 다른 이름으로 만들었다면
`deploy-main.yml` 안의 `project:` 와 `name:` 두 곳을 그 이름으로 바꾸세요.

### ③ 깃허브 Secrets 등록
저장소 → Settings → Secrets and variables → Actions → New repository secret

| 이름 | 설명 |
|---|---|
| `CLOUDTYPE_TOKEN` | 클라우드타입 개인 토큰 |
| `GHP_TOKEN` | 깃허브 Personal Access Token (repo 권한) |
| `OPENAI_API_KEY` | Realtime·STT·TTS·임베딩 공통 |
| `SMTP_PASS` | 네이버 앱 비밀번호 (topbanker99@naver.com) |
| `UPSTASH_VECTOR_URL` | Upstash Vector REST URL |
| `UPSTASH_VECTOR_TOKEN` | 읽기전용 토큰 권장 |
| `REALTIME_PW` | 상담 비밀번호 (미설정 시 기본 `2026`) |

### ④ 배포 후 필수 작업 — CORS
배포되면 `https://port-0-xxxx.sel3.cloudtype.app` 주소가 발급됩니다.
`server.js` 상단 `ALLOWED_ORIGINS`의 플레이스홀더를 **실제 주소로 교체 후 재푸시**하세요.

```js
const ALLOWED_ORIGINS = [
  'https://port-0-jongno-labor.sel3.cloudtype.app',   // ← 실제 발급 주소로 교체
  // 도메인 연결 시: 'https://www.jnhrm.co.kr',
];
```

---

## 4. 안전장치 (기본값)

| 항목 | 값 |
|---|---|
| 비밀번호 게이트 | 리얼타임 상담 진입 시 1회 (`REALTIME_PW`) |
| IP 제한 | 리얼타임 6회/시간, 절약형 150회/시간 |
| 하루 총량 | 리얼타임 10회 · 절약형 600회 · 메일 15회 |
| Turnstile | `TURNSTILE_SECRET` 설정 시에만 작동 (미설정 시 통과) |

## 5. 선택 환경변수

| 이름 | 용도 |
|---|---|
| `YT_CHANNEL_HANDLE` / `YT_CHANNEL_ID` | 유튜브 채널 개설 시 `/api/youtube/latest` 활성화 (미설정 시 404) |
| `LAW_OC` | 국가법령정보센터 판례검색 인증키 |
| `RAG_NAMESPACE` | 기본 `nomusa` |

---

## 6. 준수사항 (콘텐츠 수정 시 유지할 것)

- 공인노무사 광고규정: **허위·과장·결과보장 표현 금지**. 승소율·성공사례(결과 명시)를 넣지 마세요.
- 사전진단·AI 상담은 **참고용**이며 노무 자문을 대체하지 않는다는 고지를 유지하세요.
- RAG 상담사례의 **원문을 그대로 노출하지 마세요.**
- **판례번호·통계 수치를 창작하지 마세요.** 근거는 법령 조문으로만 표기합니다.
