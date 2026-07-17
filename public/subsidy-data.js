/* ============================================================
   노무법인 종로 · 정부지원금 간이진단 데이터
   ------------------------------------------------------------
   ★ 매년 갱신 안내 (중요)
   지원금 금액·요건은 매년(주로 연초) 개정됩니다.
   개정 시 아래 SUBSIDY_DB 배열의 값만 수정하면 사이트에 즉시 반영됩니다.
   각 항목의 maxAmount(최대금액), eligibility(요건) 텍스트를 고용노동부
   「고용장려금 지원제도」 공식 소책자 기준으로 갱신하고,
   LAST_VERIFIED 날짜를 수정하세요.
   ============================================================ */

const LAST_VERIFIED = "2026-07-18"; // 최종 검증일 — 갱신 시 반드시 수정

const SUBSIDY_DB = [
  {
    id: "youth_leap",
    name: "청년일자리도약장려금",
    org: "고용노동부 · 고용24",
    maxAmountText: "최대 720만원 / 청년 1인",
    // 요건: 우선지원대상기업(5인 이상), 만15~34세 청년 정규직 채용, 6개월 이상 유지
    match: (v) => v.size === "우선지원" && v.hiring === "yes" && v.target.includes("youth"),
    statusBadge: "신규채용 시 신청",
    reason: "만15~34세 청년을 정규직으로 신규채용하는 우선지원대상기업",
    exclusions: ["hire_promo"], // 고용촉진과 중복 시 차액
    docs: ["사업 참여신청서", "청년 취업애로 요건 증빙(실업기간·최종학력 등)", "정규직 채용 확인서류"]
  },
  {
    id: "hire_promo",
    name: "고용촉진장려금",
    org: "고용노동부 · 고용24",
    maxAmountText: "최대 720만원 / 인 (2년형은 상향)",
    // 취업지원프로그램 이수자 등 취업취약계층 실업자 신규고용
    match: (v) => v.hiring === "yes" && v.target.includes("vulnerable"),
    statusBadge: "고용일 12개월 내 신청",
    reason: "취업지원프로그램 이수자 등 취업취약계층을 신규고용한 사업주",
    exclusions: ["youth_leap"],
    docs: ["취업지원프로그램 이수 증명(내일배움카드·국민취업지원제도 등)", "실업자 확인서류"]
  },
  {
    id: "parent_leave",
    name: "출산육아기 고용안정장려금",
    org: "고용노동부 · 고용24",
    maxAmountText: "최대 570만원 / 인 (인센티브 조건부 추가)",
    // 우선지원대상기업이 육아휴직/육아기 근로시간 단축 30일 이상 허용
    match: (v) => v.size === "우선지원" && v.parentLeave === "yes",
    statusBadge: "허용·요건 충족 후 신청",
    reason: "근로자에게 육아휴직 또는 육아기 근로시간 단축을 30일 이상 허용한 우선지원대상기업",
    exclusions: [],
    docs: ["육아휴직/육아기 근로시간 단축 확인서", "대상 자녀 관계·연령 증빙", "대체인력 관련 서류(해당 시)"]
  },
  {
    id: "senior_keep",
    name: "고령자 계속고용장려금",
    org: "고용노동부 · 고용24",
    maxAmountText: "분기 최대 120만원 / 인 (비수도권), 최대 3년",
    // 정년제도 1년 이상 운영 후 계속고용제도 도입, 60세+ 계속고용
    match: (v) => v.target.includes("senior"),
    statusBadge: "분기 말일 다음날부터 1년 내",
    reason: "정년 이후 근로자를 계속고용(정년연장·폐지·재고용)하는 우선지원대상·중견기업",
    exclusions: [],
    docs: ["취업규칙·단체협약 등 계속고용제도 도입 증빙", "정년 도래·계속고용 대상자 명부"]
  },
  {
    id: "disabled_hire",
    name: "장애인 고용장려금",
    org: "한국장애인고용공단(KEAD)",
    maxAmountText: "장애정도·성별별 월 단가 (초과고용 인원분)",
    // 장애인 의무고용률 초과 고용
    match: (v) => v.target.includes("disabled"),
    statusBadge: "다음달 1일부터 3년 내 신청",
    reason: "장애인 의무고용률을 초과하여 장애인을 고용하는 사업주",
    exclusions: [],
    docs: ["장애인근로자 명부", "장애인 인정서류(복지카드·장애인증명서)", "월별 임금대장"]
  },
  {
    id: "duru",
    name: "두루누리 사회보험료 지원",
    org: "근로복지공단 · 4대사회보험",
    maxAmountText: "보험료의 80% 지원 (월 최대 약 24만원/인 경감)",
    // 10인 미만, 월평균보수 270만원 미만 신규가입
    match: (v) => (v.size === "우선지원") && (v.workers === "under10"),
    statusBadge: "상시 신청 (마감 없음)",
    reason: "근로자 10인 미만 사업의 월평균보수 270만원 미만 신규가입 근로자와 그 사업주",
    exclusions: [],
    docs: ["보험료 지원 신청서(4대사회보험 정보연계센터)", "근로자 월평균보수 확인"]
  },
  {
    id: "worklife",
    name: "워라밸일자리장려금",
    org: "고용노동부 · 노사발전재단",
    maxAmountText: "월 최대 50만원 / 인 (인프라 별도 최대 1,000만원)",
    // 소정근로시간 단축제도 도입·허용
    match: (v) => v.workTimeReduce === "yes",
    statusBadge: "단축 시작 다음달부터 12개월 내",
    reason: "근로자의 필요(육아·학업·질병 등)에 따라 소정근로시간 단축제도를 도입·허용한 사업주",
    exclusions: [],
    docs: ["소정근로시간 단축 합의서", "단축 전·후 근로시간 확인서류"]
  }
  // ※ 고용유지지원금, 사업주 직업훈련지원은 상황·서류가 복잡하여
  //   간이진단에서는 제외하고 상담 시 안내 (원하면 추가 가능)
];

/* 공통 필요서류 (대부분의 고용장려금 공통) */
const COMMON_DOCS = [
  "사업자등록증 사본",
  "4대보험 가입자명부 / 사업장 취득자 목록",
  "근로계약서(대상 근로자별)",
  "월별 임금대장(급여대장)",
  "임금지급 증빙(이체내역 등)",
  "개인정보 수집·이용 동의서"
];

if (typeof window !== "undefined") {
  window.SUBSIDY_DB = SUBSIDY_DB;
  window.SUBSIDY_COMMON_DOCS = COMMON_DOCS;
  window.SUBSIDY_LAST_VERIFIED = LAST_VERIFIED;
}
