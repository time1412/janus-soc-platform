"""가입 시 게이트웨이에 janus.com 사서함 자동 생성.

방식: SSH로 게이트웨이 접속 → virtual_users 테이블에 INSERT(+도메인 보장).
      maildir는 만들지 않는다 — Postfix/Dovecot이 첫 배달/접속 때 vmail 소유로 자동 생성한다.
      (직접 maildir를 만들면 소유권이 어긋나 'Permission denied' 배달 실패가 난다.)

⚠️ 랩 한정 단순화: 소통플랫폼이 게이트웨이 sudo 자격으로 INSERT한다.
   운영에선 INSERT 전용 DB 계정/프로비저닝 API로 대체 권장(웹앱이 메일서버 sudo를 쥐지 않게).
"""
import config

# 원격 실행 스크립트: 해시 생성 + 도메인/유저 INSERT (멱등). 인자=$1 이메일, $2 비번
_REMOTE = r'''#!/bin/bash
set -e
EMAIL="$1"; PASS="$2"; DOM="${EMAIL#*@}"
HASH=$(doveadm pw -s SHA512-CRYPT -p "$PASS")
mysql mailserver -e "INSERT INTO virtual_domains (name) SELECT '$DOM' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM virtual_domains WHERE name='$DOM');"
mysql mailserver -e "INSERT INTO virtual_users (domain_id,email,password) VALUES ((SELECT id FROM virtual_domains WHERE name='$DOM'),'$EMAIL','$HASH') ON DUPLICATE KEY UPDATE password='$HASH';"
echo "PROVISION_OK $EMAIL"
'''


def create_mailbox(email: str, password: str) -> tuple[bool, str]:
    """게이트웨이에 사서함 생성/갱신. 반환=(성공, 메시지)."""
    host = config.MAIL_SSH_HOST
    if not host:
        return False, "프로비저닝 SSH 미설정(MAIL_SSH_HOST)"
    try:
        import paramiko
    except ImportError:
        return False, "paramiko 미설치"
    user, pw = config.MAIL_SSH_USER, config.MAIL_SSH_PASSWORD
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(host, port=config.MAIL_SSH_PORT, username=user, password=pw,
                    timeout=12, look_for_keys=False, allow_agent=False)
        sftp = cli.open_sftp()
        remote = "/tmp/.soc_prov.sh"
        with sftp.file(remote, "w") as f:
            f.write(_REMOTE)
        sftp.close()
        cmd = (f"echo {pw!r} | sudo -S bash {remote} {email!r} {password!r} 2>&1; "
               f"rm -f {remote}")
        _i, out, _e = cli.exec_command(cmd, timeout=40)
        res = out.read().decode(errors="replace")
        ok = "PROVISION_OK" in res
        return ok, (res.strip() or "(출력 없음)")
    except Exception as exc:  # noqa: BLE001
        return False, f"프로비저닝 실패: {exc}"
    finally:
        try:
            cli.close()
        except Exception:
            pass
