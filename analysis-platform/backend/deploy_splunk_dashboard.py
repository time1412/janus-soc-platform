"""SOC 통합 보안 대시보드 — Splunk REST API 배포 스크립트.

실행하면:
  1. 검색 매크로 `soc_base` 생성/갱신
  2. Simple XML 대시보드 `soc_security_dashboard` 생성/갱신
"""
import sys
import requests
import urllib3

sys.path.insert(0, ".")
import config

urllib3.disable_warnings()

SPLUNK_URL = f"https://{config.SPLUNK_HOST}:{config.SPLUNK_PORT}"
AUTH = (config.SPLUNK_USERNAME, config.SPLUNK_PASSWORD)
NS = f"{SPLUNK_URL}/servicesNS/admin/search"

MACRO_NAME = "soc_base"
DASHBOARD_NAME = "soc_security_dashboard"

# ------------------------------------------------------------------
# 매크로 정의 — 대시보드 패널들이 `soc_base` 로 참조
# waf_web(nginx 웹 공격) + syslog sguild_alert(Security Onion IDS/OSSEC)
# ------------------------------------------------------------------
MACRO_DEF = (
    r'index=* sourcetype=waf_web '
    r'| rex field=_raw "^(?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[[^\]]+\] '
    r'\"(?<http_method>\S+) (?<uri>\S+) [^\"]*\" (?<status>\d{3})" '
    r'| eval dest_ip=host '
    r'| eval signature=case('
    r'match(uri,"(?i)(union.*select|%27|--|1=1)"),"SQL Injection",'
    r'match(uri,"(?i)(<script|onerror=|%3Cscript)"),"XSS",'
    r'match(uri,"(?i)(\.\./|etc/passwd)"),"Path Traversal",'
    r'true(),"HTTP Request") '
    r'| eval severity=case(signature=="SQL Injection",3,signature=="XSS",2,'
    r'signature=="Path Traversal",3,true(),1) '
    r'| eval source_type="WAF Web" '
    r'| append [search index=* sourcetype=syslog sguild_alert '
    r'| rex field=_raw "Alert Received: \d+ (?<priority>\d+) \S+ \S+ \{[^}]+\} \d+ \d+ \{(?<alert_msg>[^}]+)\} (?<src_ip>[\d.]+) (?<dest_ip>[\d.]+)" '
    r'| eval signature=case('
    r'match(alert_msg,"(?i)(sql.injection|select.*(from|user)|union.*select)"),"SQL Injection (IDS)",'
    r'match(alert_msg,"(?i)(xss|cross.site.script)"),"XSS (IDS)",'
    r'match(alert_msg,"(?i)(brute.force|invalid.user|failed.password)"),"Brute Force (IDS)",'
    r'match(alert_msg,"(?i)(port.scan|nmap|scan.detect)"),"Port Scan (IDS)",'
    r'match(alert_msg,"(?i)OSSEC"),"OSSEC: "+replace(alert_msg,"^\[OSSEC\] ",""),'
    r'true(),alert_msg) '
    r'| eval severity=case(priority=="1",3,priority=="2",3,priority=="3",2,priority=="4",2,true(),1) '
    r'| eval source_type="IDS/OSSEC" '
    r'| eval source="sguil"] '
    # ET WEB_SERVER 계열은 응답 패킷 기반 → src/dest 방향 보정
    # (bWAPP 서버가 src로 찍이는 문제 해결)
    r'| eval _sw=src_ip '
    r'| eval src_ip=if(match(signature,"(?i)ET WEB_SERVER"), dest_ip, src_ip) '
    r'| eval dest_ip=if(match(signature,"(?i)ET WEB_SERVER"), _sw, dest_ip) '
    r'| fields - _sw '
    # 인프라 장비 자체 트래픽 제외: Splunk(10.0.200.201) WAF(10.0.10.2) bWAPP서버(10.0.10.100)
    r'| where src_ip!="10.0.200.201" AND src_ip!="10.0.10.2" AND src_ip!="10.0.10.100"'
)

# ------------------------------------------------------------------
# 대시보드 XML
# ------------------------------------------------------------------
DASHBOARD_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<dashboard version="1.1" theme="dark" refresh="60">
  <label>SOC 통합 보안 대시보드</label>
  <description>WAF Web + Security Onion IDS/OSSEC 통합 실시간 이벤트 모니터링</description>

  <fieldset submitButton="false" autoRun="true">
    <input type="radio" token="earliest_tok" searchWhenChanged="true">
      <label>분석 기간</label>
      <choice value="-15m">15분</choice>
      <choice value="-1h">1시간</choice>
      <choice value="-4h">4시간</choice>
      <choice value="-24h">24시간</choice>
      <choice value="-7d">7일</choice>
      <default>-24h</default>
    </input>
    <input type="dropdown" token="sev_filter" searchWhenChanged="true">
      <label>위험도 필터</label>
      <choice value="">전체</choice>
      <choice value="| where severity=3">HIGH만</choice>
      <choice value="| where severity>=2">MEDIUM 이상</choice>
      <default></default>
    </input>
  </fieldset>

  <!-- ============================================================
       Row 0 : 소스 헬스(2) + 실시간 상태(3) = 5패널
       색상: 10분 이내=초록 / 10~30분=노랑 / 30분 초과=빨강
       ============================================================ -->
  <row>
    <panel>
      <single>
        <title>● WAF Web  마지막 수신</title>
        <search>
          <query>`soc_base` | where source_type="WAF Web" | stats latest(_time) as t | eval v=round((now()-t)/60,1) | table v</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
          <refresh>60</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[10,30]</option>
        <option name="numberPrecision">1</option>
        <option name="unit">분 전</option>
        <option name="unitPosition">after</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>● IDS/OSSEC  마지막 수신</title>
        <search>
          <query>`soc_base` | where source_type="IDS/OSSEC" | stats latest(_time) as t | eval v=round((now()-t)/60,1) | table v</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
          <refresh>60</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[10,30]</option>
        <option name="numberPrecision">1</option>
        <option name="unit">분 전</option>
        <option name="unitPosition">after</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>⚠ HIGH RISK  (Last 5 min)</title>
        <search>
          <query>`soc_base` | where severity=3 | stats count</query>
          <earliest>-5m</earliest>
          <latest>now</latest>
          <refresh>60</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xdc4e41"]</option>
        <option name="rangeValues">[1]</option>
        <option name="numberPrecision">0</option>
        <option name="unit">events</option>
        <option name="unitPosition">after</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>▲ MEDIUM RISK  (Last 5 min)</title>
        <search>
          <query>`soc_base` | where severity=2 | stats count</query>
          <earliest>-5m</earliest>
          <latest>now</latest>
          <refresh>60</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xf8be34"]</option>
        <option name="rangeValues">[1]</option>
        <option name="numberPrecision">0</option>
        <option name="unit">events</option>
        <option name="unitPosition">after</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>● TOTAL EVENTS  (Last 5 min)</title>
        <search>
          <query>`soc_base` | stats count</query>
          <earliest>-5m</earliest>
          <latest>now</latest>
          <refresh>60</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x006ba4","0x006ba4"]</option>
        <option name="rangeValues">[99999]</option>
        <option name="numberPrecision">0</option>
        <option name="unit">events</option>
        <option name="unitPosition">after</option>
      </single>
    </panel>
  </row>

  <!-- ============================================================
       Row 1 : KPI 카드 4개 (분석 기간 기준)
       ============================================================ -->
  <row>
    <panel>
      <title>전체 이벤트</title>
      <single>
        <search>
          <query>`soc_base` | stats count</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[100,500]</option>
      </single>
    </panel>
    <panel>
      <title>고위험 이벤트 (Severity 3)</title>
      <single>
        <search>
          <query>`soc_base` | where severity=3 | stats count</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xdc4e41"]</option>
        <option name="rangeValues">[1]</option>
      </single>
    </panel>
    <panel>
      <title>고유 공격 출발지 IP</title>
      <single>
        <search>
          <query>`soc_base` | where src_ip!="0.0.0.0" | stats dc(src_ip) as count</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[3,10]</option>
      </single>
    </panel>
    <panel>
      <title>IDS / OSSEC 경보</title>
      <single>
        <search>
          <query>`soc_base` | where source_type="IDS/OSSEC" | stats count</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="colorMode">block</option>
        <option name="useColors">1</option>
        <option name="rangeColors">["0x1f6e3a","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[10,50]</option>
      </single>
    </panel>
  </row>

  <!-- ============================================================
       Row 2 : ⚠ 미처리 HIGH 경보 목록 (전체 너비, 즉시 대응용)
       경과(분): 0~30=빨강(긴급) / 30~120=노랑 / 120+=회색
       ============================================================ -->
  <row>
    <panel>
      <title>⚠ HIGH 경보 — 즉시 대응 필요 (최근 20건, 분석 기간 내)</title>
      <table>
        <search>
          <query>`soc_base` | where severity=3 | eval 경과_분=round((now()-_time)/60,0) | eval Time=strftime(_time,"%Y-%m-%d %H:%M:%S") | sort -_time | head 20 | table Time, 경과_분, source_type, signature, src_ip, dest_ip, uri, status | rename 경과_분 as "경과(분)", source_type as "Source", signature as "Signature", src_ip as "Src IP", dest_ip as "Dest IP", uri as "URI", status as "Status"</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <format type="color" field="경과(분)">
          <colorPalette type="minMidMax" minColor="#dc4e41" midColor="#f8be34" maxColor="#6c757d"></colorPalette>
          <scale type="minMidMax" minValue="0" midValue="30" maxValue="120"></scale>
        </format>
        <format type="color" field="Signature">
          <colorPalette type="map">{"SQL Injection":"#dc4e41","SQL Injection (IDS)":"#dc4e41","XSS":"#f8be34","XSS (IDS)":"#f8be34","Path Traversal":"#dc4e41","Brute Force (IDS)":"#f8be34"}</colorPalette>
        </format>
        <format type="color" field="Status">
          <colorPalette type="map">{"200":"#1f6e3a","302":"#006ba4","400":"#f8be34","403":"#f8be34","404":"#6c757d","500":"#dc4e41"}</colorPalette>
        </format>
        <option name="drilldown">none</option>
        <option name="count">20</option>
        <option name="wrap">false</option>
      </table>
    </panel>
  </row>

  <!-- ============================================================
       Row 3 : 반복 공격자 분석 | 공격 유형 Top 10
       ============================================================ -->
  <row>
    <panel>
      <title>반복 공격자 분석 (최초·최근 발생 시각)</title>
      <table>
        <search>
          <query>`soc_base` | where src_ip!="0.0.0.0" | stats count as "이벤트 수", earliest(_time) as first_t, latest(_time) as last_t, values(signature) as sig_v, values(dest_ip) as ip_v by src_ip | eval "최초 발생"=strftime(first_t,"%m/%d %H:%M") | eval "최근 발생"=strftime(last_t,"%m/%d %H:%M") | eval 경과_분=round((now()-last_t)/60,0) | eval "공격 유형"=mvjoin(sig_v," / ") | eval "대상 IP"=mvjoin(ip_v,", ") | sort -"이벤트 수" | head 10 | table src_ip, "이벤트 수", "최초 발생", "최근 발생", 경과_분, "공격 유형", "대상 IP" | rename src_ip as "공격자 IP", 경과_분 as "경과(분)"</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <format type="color" field="이벤트 수">
          <colorPalette type="minMidMax" minColor="#1f6e3a" midColor="#f8be34" maxColor="#dc4e41"></colorPalette>
        </format>
        <format type="color" field="경과(분)">
          <colorPalette type="minMidMax" minColor="#dc4e41" midColor="#f8be34" maxColor="#6c757d"></colorPalette>
          <scale type="minMidMax" minValue="0" midValue="60" maxValue="480"></scale>
        </format>
        <option name="drilldown">none</option>
        <option name="count">10</option>
        <option name="wrap">true</option>
      </table>
    </panel>
    <panel>
      <title>공격 유형 Top 10  (Severity ≥ MEDIUM)</title>
      <chart>
        <search>
          <query>`soc_base` | where severity>=2 | stats count by signature | sort -count | head 10</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.showDataLabels">all</option>
        <option name="charting.legend.placement">none</option>
        <option name="charting.seriesColors">["0x00b4d8"]</option>
        <option name="charting.axisTitleX.text">이벤트 수</option>
        <option name="charting.backgroundColor">transparent</option>
        <option name="charting.foregroundColor">#adb5bd</option>
        <option name="charting.gridLinesX.showMajorLines">true</option>
        <option name="charting.gridLinesY.showMajorLines">false</option>
        <option name="charting.chart.style">shiny</option>
      </chart>
    </panel>
  </row>

  <!-- ============================================================
       Row 4 : 시간 추이 (area) + 위험도 파이
       ============================================================ -->
  <row>
    <panel>
      <title>시간대별 이벤트 추이 (소스별)</title>
      <chart>
        <search>
          <query>`soc_base` | timechart count by source_type</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.chart.nullValueMode">zero</option>
        <option name="charting.legend.placement">bottom</option>
        <option name="charting.axisTitleY.text">이벤트 수</option>
        <option name="charting.seriesColors">["0x00b4d8","0xdc4e41"]</option>
        <option name="charting.backgroundColor">transparent</option>
        <option name="charting.foregroundColor">#adb5bd</option>
        <option name="charting.gridLinesX.showMajorLines">false</option>
        <option name="charting.chart.style">shiny</option>
      </chart>
    </panel>
    <panel>
      <title>위험도별 분포</title>
      <chart>
        <search>
          <query>`soc_base` | eval sev_label=case(severity=3,"HIGH",severity=2,"MEDIUM",true(),"LOW") | stats count by sev_label | sort -count</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.seriesColors">["0xdc4e41","0xf8be34","0x1f6e3a"]</option>
        <option name="charting.legend.placement">right</option>
        <option name="charting.backgroundColor">transparent</option>
        <option name="charting.foregroundColor">#adb5bd</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
      </chart>
    </panel>
  </row>

  <!-- ============================================================
       Row 5 : 탐지 소스별 분포 + 공격 대상 서버
       ============================================================ -->
  <row>
    <panel>
      <title>탐지 소스별 이벤트 분포</title>
      <chart>
        <search>
          <query>`soc_base` | chart count over source_type by signature</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">right</option>
        <option name="charting.axisTitleX.text">이벤트 수</option>
        <option name="charting.seriesColors">["0xdc4e41","0x00b4d8","0xf8be34","0x1f6e3a","0x9b59b6","0xe67e22"]</option>
        <option name="charting.backgroundColor">transparent</option>
        <option name="charting.foregroundColor">#adb5bd</option>
        <option name="charting.chart.style">shiny</option>
        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>
      </chart>
    </panel>
    <panel>
      <title>공격 대상 서버 (dest_ip)</title>
      <table>
        <search>
          <query>`soc_base` | where dest_ip!="0.0.0.0" AND isnotnull(dest_ip) | stats count as "이벤트 수", values(signature) as sig_v by dest_ip | eval "주요 시그니처"=mvjoin(sig_v," / ") | sort -"이벤트 수" | head 10 | table dest_ip, "이벤트 수", "주요 시그니처" | rename dest_ip as "목적지 IP"</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <format type="color" field="이벤트 수">
          <colorPalette type="minMidMax" minColor="#1f6e3a" midColor="#f8be34" maxColor="#dc4e41"></colorPalette>
        </format>
        <option name="drilldown">none</option>
        <option name="count">10</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>

  <!-- ============================================================
       Row 6 : 전체 이벤트 목록 (전체 너비)
       ============================================================ -->
  <row>
    <panel>
      <title>보안 이벤트 목록 (최대 50건)</title>
      <table>
        <search>
          <query>`soc_base` $sev_filter$ | eval Severity=case(severity=3,"HIGH",severity=2,"MEDIUM",true(),"LOW") | eval Time=strftime(_time,"%Y-%m-%d %H:%M:%S") | sort -_time | head 50 | table Time, source_type, signature, Severity, src_ip, dest_ip, uri, status | rename source_type as "Source", signature as "Signature", src_ip as "Src IP", dest_ip as "Dest IP", uri as "URI", status as "Status"</query>
          <earliest>$earliest_tok$</earliest>
          <latest>now</latest>
        </search>
        <format type="color" field="Severity">
          <colorPalette type="map">{"HIGH":"#dc4e41","MEDIUM":"#f8be34","LOW":"#53a051"}</colorPalette>
        </format>
        <format type="color" field="Status">
          <colorPalette type="map">{"200":"#1f6e3a","302":"#006ba4","400":"#f8be34","403":"#f8be34","404":"#6c757d","500":"#dc4e41"}</colorPalette>
        </format>
        <option name="drilldown">none</option>
        <option name="count">25</option>
        <option name="wrap">false</option>
      </table>
    </panel>
  </row>

</dashboard>
"""


# ------------------------------------------------------------------
# 배포 함수
# ------------------------------------------------------------------

def _post(url: str, data: dict) -> tuple[int, str]:
    r = requests.post(url, auth=AUTH, verify=False, data=data, timeout=30)
    return r.status_code, r.text


def upsert_macro(name: str, definition: str) -> None:
    """매크로를 생성하거나 이미 있으면 갱신한다.

    Splunk 버전에 따라 /configs/conf-macros 엔드포인트를 사용한다.
    """
    # 갱신 시도 (이미 존재하는 경우)
    update_url = f"{NS}/configs/conf-macros/{name}"
    status, body = _post(update_url, {"definition": definition})
    if status == 404:
        # 신규 생성
        status, body = _post(
            f"{NS}/configs/conf-macros",
            {"name": name, "definition": definition},
        )
    if status in (200, 201):
        print(f"  [OK] 매크로 `{name}` 배포 완료 (HTTP {status})")
    else:
        print(f"  [ERR] 매크로 배포 실패 (HTTP {status})")
        print(f"        {body[:400]}")


def upsert_dashboard(name: str, xml: str) -> None:
    """대시보드를 생성하거나 이미 있으면 갱신한다."""
    update_url = f"{NS}/data/ui/views/{name}"
    status, body = _post(update_url, {"eai:data": xml})
    if status == 404:
        status, body = _post(
            f"{NS}/data/ui/views",
            {"name": name, "eai:data": xml},
        )
    if status in (200, 201):
        print(f"  [OK] 대시보드 `{name}` 배포 완료 (HTTP {status})")
    else:
        print(f"  [ERR] 대시보드 배포 실패 (HTTP {status})")
        print(f"        {body[:400]}")


def set_global_sharing(resource_type: str, name: str) -> None:
    """앱 전체에서 접근 가능하도록 공유 설정."""
    url = f"{NS}/{resource_type}/{name}/acl"
    status, _ = _post(url, {"sharing": "app", "owner": "admin", "perms.read": "*"})
    if status in (200, 201):
        print(f"  [OK] 공유 설정 완료 ({resource_type}/{name})")


if __name__ == "__main__":
    print("=" * 55)
    print("SOC 통합 보안 대시보드 배포")
    print(f"대상: {SPLUNK_URL}")
    print("=" * 55)

    print("\n[1/3] 검색 매크로 `soc_base` 배포 중...")
    upsert_macro(MACRO_NAME, MACRO_DEF)
    set_global_sharing("search/macros", MACRO_NAME)

    print("\n[2/3] 대시보드 XML 배포 중...")
    upsert_dashboard(DASHBOARD_NAME, DASHBOARD_XML)
    set_global_sharing("data/ui/views", DASHBOARD_NAME)

    print("\n[3/3] 완료!")
    print(f"\n접속 URL:")
    print(f"  https://{config.SPLUNK_HOST}:8000/en-US/app/search/{DASHBOARD_NAME}")
    print()
