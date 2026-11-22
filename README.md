# rag-data

AI 상담 사례 데이터(v2)를 암호를 건 파일로만 보관하는 가지입니다.

- nomusa_v2.jsonl.gpg: AES-256 대칭 암호(gpg). 암호는 저장소 비밀값 RAG_DATA_KEY에만 있습니다.
- 수동 실행 워크플로 .github/workflows/rag-upload.yml(main)이 이 파일을 받아 실행 중에만 풀고, Upstash 묶음 nomusa-v2에 올립니다.
- 이 가지에는 워크플로 파일이 없어 push해도 배포가 돌지 않습니다.
- 올리기가 끝나 더 쓸 일이 없으면 이 가지를 지워도 됩니다(이미 받아 간 사본은 회수할 수 없으니, 암호를 새어 나가지 않게 관리).
