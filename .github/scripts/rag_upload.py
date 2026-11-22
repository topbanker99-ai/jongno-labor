"""AI 상담 사례 DB v2 올리기 (GitHub Actions 수동 실행 전용, 표준 라이브러리만 사용)

공개 저장소라 실행 기록(로그)은 누구나 볼 수 있다.
그래서 이 프로그램은 사례 글(질문·답변)과 토큰·주소를 절대 출력하지 않는다. 건수, 번호(id), 점수, 상태 코드만 출력한다.

저장소(인덱스) 두 곳
- 기존: 공동 개발자 인덱스(UPSTASH_OLD_URL/UPSTASH_OLD_TOKEN, 묶음 nomusa). **읽기만 한다.**
  이 연결로는 조회(/info, /range, /query) 말고 어떤 요청도 보내지 않도록 코드로 막았다.
- 새것: 대표 인덱스(KL_URL). 쓰기는 KL_WRITE_TOKEN, 검색 비교는 KL_READ_TOKEN(홈페이지와 같은 읽기 전용 토큰).
  두 주소가 같으면(새 인덱스 주소에 기존 주소를 잘못 넣은 경우) 아무것도 하지 않고 멈춘다.

MODE=check  : 두 인덱스 정보(건수·차원), 기존 묶음 항목 형식(이름만), 대표 인덱스 쓰기 토큰·읽기 토큰 권한,
              암호 파일 풀림 여부를 확인한다. 사례는 쓰지 않는다(권한 시험은 빈 목록이라 저장되는 것 없음).
              nomusa-v2에 자료가 있으면 시험 질문 8개로 기존 nomusa 와 새 nomusa-v2 검색 결과(번호·점수만)를 견준다.
MODE=upload : 암호 푼 파일 → 주제 불일치 점검 → 질문 임베딩 → 대표 인덱스 nomusa-v2에 나눠 올리기
              (이미 올라간 번호는 건너뜀 = 다음 날 다시 누르면 이어 올리기). MAX_UPSERT=0 이면 점검 결과만 내고 올리지 않는다.
"""
import json, math, os, re, sys, time, urllib.request, urllib.error

NS_TARGET = os.environ.get('RAG_TARGET_NAMESPACE', 'nomusa-v2')
NS_OLD = 'nomusa'
MODE = os.environ.get('MODE', 'check')
DATA = os.environ.get('DATA_FILE', '')


def _url(name):
    return os.environ.get(name, '').strip().strip('"\'').rstrip('/')


def _tok(name):
    return os.environ.get(name, '').strip().strip('"\'')


OLD_URL, OLD_TOKEN = _url('UPSTASH_OLD_URL'), _tok('UPSTASH_OLD_TOKEN')
KL_URL = _url('KL_URL')
KL_WRITE_TOKEN, KL_READ_TOKEN = _tok('KL_WRITE_TOKEN'), _tok('KL_READ_TOKEN')
OA_KEY = os.environ.get('OPENAI_API_KEY', '').strip()
OA_BASE = (os.environ.get('OPENAI_BASE_URL') or 'https://api.openai.com').rstrip('/')
FLOOR = float(os.environ.get('MISMATCH_FLOOR') or 0.25)
MAX_RATIO = float(os.environ.get('MISMATCH_MAX_RATIO') or 0.03)
MAX_UPSERT = int(os.environ.get('MAX_UPSERT') or 9000)
OUT_DIR = os.environ.get('RESULT_DIR', '.')
EMB_MODEL, EMB_DIM, HEAD_CHARS = 'text-embedding-3-small', 512, 300

if NS_TARGET in ('', NS_OLD):
    sys.exit('중단: 올릴 묶음 이름이 비었거나 기존 묶음(nomusa)입니다. 기존 묶음은 건드리지 않습니다.')


def log(*a):
    print(*a, flush=True)


def _host(u):
    return re.sub(r'^https?://', '', u.lower()).split('/')[0]


def http(method, url, body=None, headers=None, tries=6, timeout=60):
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode('utf-8')
    h = {'Content-Type': 'application/json'}
    h.update(headers or {})
    for i in range(tries):
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode('utf-8') or 'null')
        except urllib.error.HTTPError as e:
            code = e.code
            try:
                e.read()  # 응답 본문은 출력하지 않는다
            except Exception:
                pass
            if code in (429, 500, 502, 503, 504) and i < tries - 1:
                time.sleep(min(60, 2 ** i * 2)); continue
            return code, None
        except Exception as e:  # 네트워크 오류(주소·토큰이 담긴 메시지는 출력하지 않음)
            if i < tries - 1:
                time.sleep(min(60, 2 ** i * 2)); continue
            log('  네트워크 오류 종류:', type(e).__name__)
            return -1, None


# 기존 인덱스에 보낼 수 있는 요청: 조회 세 가지뿐. 그 밖의 경로(upsert·delete·reset·update 등)는 보내기 전에 멈춘다.

class Index:
    def __init__(self, label, url, token, writable):
        self.label, self.url, self.token, self.writable = label, url, token, writable

    def req(self, method, path, body=None):
        if not self.writable and not (path == '/info' or path.startswith(('/range/', '/query/'))):
            sys.exit(f'중단: {self.label} 연결로 조회가 아닌 요청({path.split("/")[1]})을 보내려 했습니다. 코드 오류입니다.')
        if self.writable and OLD_URL and _host(self.url) == _host(OLD_URL):
            sys.exit('중단: 쓰기 대상 주소가 기존(공동 개발자) 인덱스와 같습니다. 비밀값을 확인하세요.')
        return http(method, f'{self.url}{path}', body, {'Authorization': f'Bearer {self.token}'})


def connections():
    """세 연결을 만든다. 기존은 읽기 전용(writable=False)로만 만든다."""
    old = Index('기존(공동 개발자) 인덱스', OLD_URL, OLD_TOKEN, writable=False) if OLD_URL and OLD_TOKEN else None
    new_w = Index('대표 인덱스(쓰기 토큰)', KL_URL, KL_WRITE_TOKEN, writable=True) if KL_URL and KL_WRITE_TOKEN else None
    new_r = Index('대표 인덱스(읽기 토큰)', KL_URL, KL_READ_TOKEN, writable=False) if KL_URL and KL_READ_TOKEN else None
    if KL_URL and OLD_URL and _host(KL_URL) == _host(OLD_URL):
        sys.exit('중단: KL_UPSTASH_URL 이 기존(공동 개발자) 인덱스 주소와 같습니다. 대표 인덱스 주소를 넣어 주세요.')
    return old, new_w, new_r


def unwrap(j):
    return j.get('result', j) if isinstance(j, dict) else j


def shape(s):
    # 번호 모양만 보여 준다(예: 노동자-9999). 글자 내용이 아니라 형식 확인용.
    return re.sub(r'\d', '9', str(s))[:40]


def info(ix):
    code, j = ix.req('GET', '/info')
    if code != 200:
        log(f'  {ix.label} /info 상태 코드', code); return None
    return unwrap(j)


def show_info(ix, i):
    log('  차원', i.get('dimension'), '/ 유사도', i.get('similarityFunction'), '/ 전체 건수', i.get('vectorCount'),
        '/ 대기', i.get('pendingVectorCount'))
    for name, v in sorted((i.get('namespaces') or {}).items()):
        log(f"  묶음 '{name or '(기본)'}': {v.get('vectorCount')}건 (대기 {v.get('pendingVectorCount')})")
    if i.get('dimension') != EMB_DIM:
        log(f'  주의: 차원이 {EMB_DIM}이 아닙니다.')


def range_ids(ix, ns, with_meta=False, limit=1000, max_pages=None):
    cur, ids, metas, pages = '0', [], [], 0
    while True:
        body = {'cursor': cur, 'limit': limit, 'includeMetadata': with_meta, 'includeVectors': False}
        code, j = ix.req('GET', f'/range/{ns}', body)
        if code == 405:
            code, j = ix.req('POST', f'/range/{ns}', body)
        if code != 200:
            log(f'  /range/{ns} 상태 코드', code); return None, None
        r = unwrap(j) or {}
        for v in r.get('vectors', []):
            ids.append(v.get('id')); metas.append(v.get('metadata'))
        cur = r.get('nextCursor') or ''
        pages += 1
        if not cur or (max_pages and pages >= max_pages):
            return ids, metas


def load_data():
    rows = []
    with open(DATA, encoding='utf-8') as f:
        for n, line in enumerate(f, 1):
            o = json.loads(line)
            md = o.get('metadata') or {}
            assert o.get('id') and o.get('embed') and md.get('answer') and md.get('type'), f'{n}번째 줄 형식 오류'
            assert md.get('perspective') in ('노동자', '사업주'), f'{n}번째 줄 관점 값 오류'
            rows.append(o)
    ids = [o['id'] for o in rows]
    assert len(ids) == len(set(ids)), '번호 중복'
    return rows


def perm_verdict(code):
    # 빈 목록 올리기 시험: 인증을 통과하면 내용 검사에서 걸려 422(또는 400)가 나오고, 저장되는 것은 없다.
    if code in (200, 400, 422):
        return '인증 통과·쓰기 가능'
    if code in (401, 403):
        return '쓰기 불가(읽기 전용 토큰이거나 토큰 오류)'
    return '판단 못함'


def check():
    old, new_w, new_r = connections()
    log('== 1. 기존(공동 개발자) 인덱스 정보 — 읽기만')
    i_old = info(old) if old else log('  비밀값 UPSTASH_VECTOR_URL/TOKEN 없음 → 건너뜀')
    if i_old:
        show_info(old, i_old)
    log('== 2. 대표 인덱스 정보')
    new_any = new_r or new_w
    i_new = info(new_any) if new_any else log('  비밀값 KL_UPSTASH_URL/토큰 없음 → 건너뜀')
    if i_new:
        show_info(new_any, i_new)
        if i_new.get('similarityFunction') and str(i_new.get('similarityFunction')).upper() != 'COSINE':
            log('  주의: 유사도 방식이 COSINE이 아닙니다.')
    if old:
        log(f"== 3. 기존 묶음 '{NS_OLD}' 항목 형식(값은 출력하지 않음)")
        ids, metas = range_ids(old, NS_OLD, with_meta=True, limit=3, max_pages=1)
        for k, (vid, md) in enumerate(zip(ids or [], metas or []), 1):
            keys = {kk: type(vv).__name__ for kk, vv in (md or {}).items()}
            log(f'  표본{k}: 번호 모양 {shape(vid)} / metadata 이름·형식 {keys}')
    log('== 4. 대표 인덱스 토큰 권한(빈 목록을 시험 묶음에 보내 상태 코드만 봄, 저장되는 것 없음, 기존 인덱스에는 보내지 않음)')
    if new_w:
        code, _ = new_w.req('POST', f'/upsert/{NS_TARGET}-permcheck', [])
        log('  쓰기 토큰: 상태 코드', code, '→', perm_verdict(code))
    else:
        log('  쓰기 토큰 비밀값(KL_UPSTASH_WRITE_TOKEN) 없음')
    if new_r:
        # 읽기 토큰은 일부러 쓰기 가능 연결로 따로 만들어 시험한다(같은 대표 인덱스, 빈 목록).
        probe = Index('대표 인덱스(읽기 토큰 시험)', KL_URL, KL_READ_TOKEN, writable=True)
        code, _ = probe.req('POST', f'/upsert/{NS_TARGET}-permcheck', [])
        ok = code in (401, 403)
        log('  읽기 토큰: 상태 코드', code, '→', '쓰기 막힘(정상, 홈페이지용으로 적합)' if ok else
            f'주의: 쓰기가 막히지 않은 것으로 보입니다({perm_verdict(code)}). 홈페이지에 넣기 전에 토큰 종류를 확인하세요.')
    else:
        log('  읽기 토큰 비밀값(KL_UPSTASH_READ_TOKEN) 없음')
    if DATA and os.path.exists(DATA):
        log('== 5. 암호 파일 풀림 확인(내용은 출력하지 않음)')
        rows = load_data()
        n_case = sum(1 for o in rows if not re.search(r'-a\d$', o['id']))
        log(f'  항목 {len(rows)}개(사례 {n_case}건), 주제 점검 대상 {sum(1 for o in rows if o.get("check"))}개 — 형식 이상 없음')
    v2 = ((i_new or {}).get('namespaces') or {}).get(NS_TARGET) or {}
    if not v2.get('vectorCount'):
        log(f"== 6. 검색 비교: 대표 인덱스 '{NS_TARGET}'가 아직 비어 있어 건너뜀")
        return
    if not (OA_KEY and old and new_r):
        log('== 6. 검색 비교: OPENAI_API_KEY·기존 인덱스·대표 읽기 토큰 중 빠진 것이 있어 건너뜀')
        return
    log(f"== 6. 시험 질문 검색 비교(읽기만, 번호·점수만 출력) — 기존 '{NS_OLD}' 대 대표 '{NS_TARGET}'(읽기 토큰)")
    qs = embed([q for q, _ in TEST_QUESTIONS])
    for (q, persp), vec in zip(TEST_QUESTIONS, qs):
        log(f'  [{q}] ({persp})')
        for tag, ix, ns in (('기존', old, NS_OLD), ('대표', new_r, NS_TARGET)):
            body = {'vector': vec, 'topK': 3, 'includeMetadata': False, 'filter': f"perspective = '{persp}'"}
            code, j = ix.req('POST', f'/query/{ns}', body)
            res = unwrap(j) if code == 200 else None
            hits = ', '.join(f"{m.get('id')}({m.get('score', 0):.2f})" for m in (res or [])) if res is not None else f'상태 코드 {code}'
            log(f'    {tag} {ns:>10}: {hits}')
    log('  (0.35 미만은 홈페이지가 버리는 점수. 번호로 PC의 Word 정리본·nomusa_v2.jsonl에서 내용을 확인)')


# 시험 질문: 일반적인 노무 질문만(의뢰인·사건 내용 아님). 관점 필터는 홈페이지와 같은 방식.
TEST_QUESTIONS = [
    ('퇴사하면 남은 연차는 수당으로 받을 수 있나요', '노동자'),
    ('알바도 주휴수당을 받을 수 있나요', '노동자'),
    ('권고사직이면 실업급여를 받을 수 있나요', '노동자'),
    ('해고당했는데 부당해고 구제신청은 언제까지 해야 하나요', '노동자'),
    ('직원이 1년 안 채우고 그만두면 퇴직금을 줘야 하나요', '사업주'),
    ('공휴일에 일한 직원에게 수당을 얼마나 줘야 하나요', '사업주'),
    ('수습 직원 월급을 최저임금보다 적게 줘도 되나요', '사업주'),
    ('직장 내 괴롭힘 신고가 들어오면 회사는 무엇을 해야 하나요', '사업주'),
]


def embed(texts):
    out = []
    for s in range(0, len(texts), 100):
        batch = [t[:2000] for t in texts[s:s + 100]]
        code, j = http('POST', f'{OA_BASE}/v1/embeddings', {'model': EMB_MODEL, 'input': batch, 'dimensions': EMB_DIM},
                       {'Authorization': f'Bearer {OA_KEY}'}, timeout=120)
        if code != 200:
            sys.exit(f'임베딩 실패: 상태 코드 {code} (위치 {s})')
        data = sorted(j['data'], key=lambda d: d['index'])
        out.extend(d['embedding'] for d in data)
        if (s // 100) % 20 == 0:
            log(f'  임베딩 {min(s + 100, len(texts))}/{len(texts)}')
    return out


def cos(a, b):
    na = math.sqrt(sum(x * x for x in a)); nb = math.sqrt(sum(x * x for x in b))
    return sum(x * y for x, y in zip(a, b)) / (na * nb) if na and nb else 0.0


def pct(v, p):
    v = sorted(v); return v[min(len(v) - 1, int(len(v) * p))] if v else None


def upload():
    _, new_w, _ = connections()   # 올리기는 대표 인덱스 쓰기 토큰 하나만 쓴다. 기존 인덱스 연결은 쓰지 않는다.
    if not new_w:
        sys.exit('KL_UPSTASH_URL 또는 KL_UPSTASH_WRITE_TOKEN 비밀값이 없습니다.')
    rows = load_data()
    log(f'== 1. 자료: 항목 {len(rows)}개')
    if not OA_KEY:
        sys.exit('OPENAI_API_KEY 비밀값이 없습니다.')
    log('== 2. 질문 임베딩')
    qv = embed([o['embed'] for o in rows])
    chk = [k for k, o in enumerate(rows) if o.get('check')]
    log(f'== 3. 주제 불일치 점검: 대상 {len(chk)}개(보완 답·블로그 문답은 점검 제외)')
    av = embed([rows[k]['metadata']['answer'][:HEAD_CHARS] for k in chk])
    sims = {k: cos(qv[k], a) for k, a in zip(chk, av)}
    vals = list(sims.values())
    if vals:
        log('  닮은 정도 분포(하위 1%·5%·10%·50%):', *[round(pct(vals, p), 3) for p in (0.01, 0.05, 0.10, 0.50)])
    for t in (0.15, 0.20, 0.25, 0.30, 0.35):
        log(f'  {t:.2f} 미만: {sum(1 for v in vals if v < t)}개')
    low = sorted([k for k in chk if sims[k] < FLOOR], key=lambda k: sims[k])
    cap = int(len(chk) * MAX_RATIO)
    if len(low) > cap:
        log(f'  하한 {FLOOR} 미만이 {len(low)}개로 상한({MAX_RATIO:.0%}, {cap}개)을 넘어 가장 낮은 {cap}개만 뺍니다.')
        low = low[:cap]
    excl = {rows[k]['id'] for k in low}
    log(f'  뺀 항목 {len(excl)}개 (하한 {FLOOR}, 상한 {MAX_RATIO:.0%})')
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, 'topic_excluded.csv'), 'w', encoding='utf-8') as f:
        f.write('id,score\n')
        for k in low:
            f.write(f"{rows[k]['id']},{sims[k]:.4f}\n")
    with open(os.path.join(OUT_DIR, 'topic_scores_summary.json'), 'w', encoding='utf-8') as f:
        json.dump({'targets': len(chk), 'floor': FLOOR, 'max_ratio': MAX_RATIO, 'excluded': len(excl),
                   'p01': pct(vals, 0.01), 'p05': pct(vals, 0.05), 'p10': pct(vals, 0.10), 'p50': pct(vals, 0.50)}, f)
    log('  뺀 번호:', ' '.join(sorted(excl)) if excl else '없음')
    log(f"== 4. 대표 인덱스 '{NS_TARGET}'에 이미 있는 번호 확인(이어 올리기)")
    have, _ = range_ids(new_w, NS_TARGET)
    if have is None:
        have = []
        log('  (묶음이 아직 없거나 조회 실패 → 처음부터 올림)')
    have = set(have)
    todo = [k for k, o in enumerate(rows) if o['id'] not in excl and o['id'] not in have]
    log(f'  이미 있음 {len(have)}개 / 올릴 것 {len(todo)}개 / 이번 실행 상한 {MAX_UPSERT}개')
    done = 0
    for s in range(0, min(len(todo), MAX_UPSERT), 100):
        part = todo[s:min(s + 100, MAX_UPSERT)]
        body = [{'id': rows[k]['id'], 'vector': qv[k], 'metadata': rows[k]['metadata']} for k in part]
        code, _ = new_w.req('POST', f'/upsert/{NS_TARGET}', body)
        if code != 200:
            log(f'  올리기 실패: 상태 코드 {code} — 지금까지 {done}개 올림. 하루 한도면 내일 같은 버튼을 다시 누르면 이어서 올립니다.')
            break
        done += len(part)
        if (s // 100) % 10 == 0:
            log(f'  올림 {done}개')
    left = len(todo) - done
    log(f'== 5. 결과: 이번에 올림 {done}개 / 남은 것 {left}개 / 주제 점검으로 뺀 것 {len(excl)}개')
    if left:
        log('  남은 것이 있습니다. 다음 날 mode=upload로 다시 실행하면 이어서 올립니다.')
    if MAX_UPSERT > 0:
        time.sleep(5)
    i = info(new_w)
    if i:
        v = (i.get('namespaces') or {}).get(NS_TARGET) or {}
        log(f"  대표 인덱스 '{NS_TARGET}' 현재 {v.get('vectorCount')}건 (대기 {v.get('pendingVectorCount')}) — 반영에 시간이 걸릴 수 있음")
    if done == 0 and left and MAX_UPSERT > 0:
        sys.exit(1)


if __name__ == '__main__':
    log(f'모드 {MODE} / 대상: 대표 인덱스 묶음 {NS_TARGET} (기존 인덱스는 읽기만)')
    check() if MODE == 'check' else upload() if MODE == 'upload' else sys.exit('mode는 check 또는 upload')
