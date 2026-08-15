# Copy style rules (user-facing surfaces)

적용 대상: 사용자·고객에게 노출되는 모든 것. 터미널 출력, HTML 리포트, 공유 카드,
CLI 메시지, README, 랜딩 페이지, 문서, 에러 메시지. 앞으로 만드는 것 전부 포함.

## 규칙

1. **긴 대시 금지.** em dash(—), en dash(–)를 문장에 쓰지 않는다.
   쉼표, 마침표, 콜론, 괄호로 대체한다. 테이블의 빈값 표시는 ASCII 하이픈(-).
   이 규칙은 테스트로 강제된다 (렌더 산출물에 U+2014, U+2013 존재 시 실패).
2. **AI 문체 패턴 금지.**
   - "It's not X, it's Y" 대구 구조 남발 금지
   - "delve", "landscape", "seamless", "robust", "leverage" 류 금지
   - 모든 문장이 같은 길이·같은 리듬으로 반복되는 병렬 구조 금지
   - 과잉 콜론 구조("Here's the thing:") 금지
3. **개발자 도구의 목소리로 쓴다.** 짧게, 사실만, 소문자 시작 허용.
   좋은 예: "estimate only. assumes logged bytes match billed transfer."
   나쁜 예: "This is merely an estimate — actual results may vary significantly."
4. **과장 금지는 기존 정직 원칙과 동일.** 숫자에는 근거, 추정에는 공식.

## 이유

타깃 사용자(HN, r/selfhosted의 개발자)는 AI 생성 문체를 가장 빨리 감지하는
집단이고, 감지되는 순간 도구 자체의 신뢰가 떨어진다. 문체는 디자인의 일부다.
