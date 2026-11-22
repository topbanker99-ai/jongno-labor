"""AI 상담 사례 DB v2 올리기 (GitHub Actions 수동 실행 전용, 표준 라이브러리만 사용)

공개 저장소라 실행 기록(로그)은 누구나 볼 수 있다.
그래서 이 프로그램은 사례 글(질문·답변)을 절대 출력하지 않는다. 건수, 번호(id), 점수, 상태 코드만 출력한다.

MODE=check  : 기존 묶음 정보(건수·차원·항목 형식 이름만), 토큰 쓰기 권한, 암호 파일 풀림 여부만 확인. 아무것도 쓰지 않는다.
              nomusa-v2가 이미 있으면 시험 질문 8개로 nomusa와 nomusa-v2 검색 결과(번호·점수만)를 견준다.
MODE=upload : 암호 푼 파일 → 주제 불일치 점검 → 질문 임베딩 → nomusa-v2에 나눠 올리기(이미 올라간 번호는 건너뜀).
              MAX_UPSERT=0 으로 실행하면 점검 결과만 내고 올리지 않는다.
"""
import json, math, os, re, sys, time, urllib.request, urllib.error

NS_TARGET = os.environ.get('RAG_TARGET_NAMESPACE', 'nomusa-v2')
NS_OLD = 'nomusa'
MODE = os.environ.get('MODE', 'check')
DATA = os.environ.get('DATA_FILE', '')
UP_URL = os.environ.get('UPSTASH_URL', '').strip().rstrip('/')
UP_TOKEN = os.environ.get('UPSTASH_TOKEN', '').strip()
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
        except Exception as e:  # 네트워크 오류
            if i < tries - 1:
                time.sleep(min(60, 2 ** i * 2)); continue
            log('  네트워크 오류 종류:', type(e).__name__)
            return -1, None


def up(method, path, body=None):
    return http(method, f'{UP_URL}{path}', body, {'Authorization': f'Bearer {UP_TOKEN}'})


def unwrap(j):
    return j.get('result', j) if isinstance(j, dict) else j


def shape(s):
    # 번호 모양만 보여 준다(예: 노동자-9999). 글자 내용이 아니라 형식 확인용.
    return re.sub(r'\d', '9', str(s))[:40]


def info():
    code, j = up('GET', '/info')
    if code != 200:
        log('  /info 상태 코드', code); return None
    return unwrap(j)


def range_ids(ns, with_meta=False, limit=1000, max_pages=None):
    cur, ids, metas, pages = '0', [], [], 0
    while True:
        body = {'cursor': cur, 'limit': limit, 'includeMetadata': with_meta, 'includeVectors': False}
        code, j = up('GET', f'/range/{ns}', body)
        if code == 405:
            code, j = up('POST', f'/range/{ns}', body)
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


def check():
    log('== 1. 저장소 정보(/info)')
    i = info()
    if i:
        log('  차원', i.get('dimension'), '/ 유사도', i.get('similarityFunction'), '/ 전체 건수', i.get('vectorCount'),
            '/ 대기', i.get('pendingVectorCount'))
        for name, v in sorted((i.get('namespaces') or {}).items()):
            log(f"  묶음 '{name}': {v.get('vectorCount')}건 (대기 {v.get('pendingVectorCount')})")
        if i.get('dimension') != EMB_DIM:
            log(f'  주의: 차원이 {EMB_DIM}이 아닙니다.')
    log(f"== 2. 기존 묶음 '{NS_OLD}' 항목 형식(값은 출력하지 않음)")
    ids, metas = range_ids(NS_OLD, with_meta=True, limit=3, max_pages=1)
    if ids is not None:
        for k, (vid, md) in enumerate(zip(ids, metas), 1):
            keys = {kk: type(vv).__name__ for kk, vv in (md or {}).items()}
            log(f'  표본{k}: 번호 모양 {shape(vid)} / metadata 이름·형식 {keys}')
    log('== 3. 토큰 쓰기 권한(빈 목록을 시험 묶음에 보내 상태 코드만 봄, 저장되는 것 없음)')
    code, _ = up('POST', f'/upsert/{NS_TARGET}-permcheck', [])
    verdict = '쓰기 불가(읽기 전용이거나 토큰 오류)' if code in (401, 403) else '쓰기 가능으로 보임' if code in (200, 400, 422) else '판단 못함'
    log('  상태 코드', code, '→', verdict)
    if DATA and os.path.exists(DATA):
        log('== 4. 암호 파일 풀림 확인(내용은 출력하지 않음)')
        rows = load_data()
        n_case = sum(1 for o in rows if not re.search(r'-a\d$', o['id']))
        log(f'  항목 {len(rows)}개(사례 {n_case}건), 주제 점검 대상 {sum(1 for o in rows if o.get("check"))}개 — 형식 이상 없음')
    v2 = ((i or {}).get('namespaces') or {}).get(NS_TARGET) or {}
    if v2.get('vectorCount') and OA_KEY:
        log(f"== 5. 시험 질문 검색 비교(읽기만, 번호·점수만 출력) — '{NS_OLD}' 대 '{NS_TARGET}'")
        qs = embed([q for q, _ in TEST_QUESTIONS])
        for (q, persp), vec in zip(TEST_QUESTIONS, qs):
            log(f'  [{q}] ({persp})')
            for ns in (NS_OLD, NS_TARGET):
                body = {'vector': vec, 'topK': 3, 'includeMetadata': True, 'filter': f"perspective = '{persp}'"}
                code, j = up('POST', f'/query/{ns}', body)
                res = unwrap(j) if code == 200 else None
                hits = ', '.join(f"{m.get('id')}({m.get('score', 0):.2f})" for m in (res or [])) if res is not None else f'상태 코드 {code}'
                log(f'    {ns:>10}: {hits}')
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
    log(f"== 4. '{NS_TARGET}'에 이미 있는 번호 확인")
    have, _ = range_ids(NS_TARGET)
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
        code, _ = up('POST', f'/upsert/{NS_TARGET}', body)
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
    time.sleep(5)
    i = info()
    if i:
        v = (i.get('namespaces') or {}).get(NS_TARGET) or {}
        log(f"  '{NS_TARGET}' 현재 {v.get('vectorCount')}건 (대기 {v.get('pendingVectorCount')}) — 반영에 시간이 걸릴 수 있음")
    if done == 0 and left and MAX_UPSERT > 0:
        sys.exit(1)


if __name__ == '__main__':
    if not UP_URL or not UP_TOKEN:
        sys.exit('UPSTASH_VECTOR_URL 또는 토큰 비밀값이 없습니다.')
    log(f'모드 {MODE} / 대상 묶음 {NS_TARGET}')
    check() if MODE == 'check' else upload() if MODE == 'upload' else sys.exit('mode는 check 또는 upload')
