"use strict";
document.querySelector("#view-account .page-heading").insertAdjacentHTML("beforeend", '<button id="account-logout" class="secondary">로그아웃</button>');
$("#account-logout").onclick = () => $("#logout").click();
// Appliance enrollment is a control plane, not a claim of log replication.
document.querySelector("#view-cluster").innerHTML = `
<div class="page-heading"><div><p class="eyebrow">CONNECTED APPLIANCES</p><h1>함께 연결하다.</h1><p>동일한 제품, 동일한 버전. 한 대의 Master가 장비 가입 순서를 관리합니다.</p></div><button id="cluster-refresh" class="secondary">↻ 상태 새로고침</button></div>
<div id="cluster-access" class="warning" hidden></div>
<div class="metrics" id="cluster-metrics"></div>
<div class="warning" id="cluster-data-warning">장비 가입과 데이터 복제는 다릅니다. 아래 가입 절차는 Master/Slave 구성원을 등록하며, 로그·계정·정책의 자동 복제나 장애 전환을 활성화하지 않습니다.</div>
<article id="cluster-enrollment" hidden><div class="signal-topline"><div><p class="signal-kicker">CHOOSE YOUR ROLE</p><h2>이 장비의 역할</h2></div><span class="cluster-role">동일 버전만 연결</span></div>
<div class="cluster-stage"><button class="role-choice" id="choose-master" aria-pressed="false"><span>01 / CREATE A GROUP</span><strong>Master</strong><p>새 클러스터를 만들고 가입 번호를 배정합니다.<br>그룹에는 Master 한 대만 존재합니다.</p></button><button class="role-choice" id="choose-slave" aria-pressed="false"><span>02 / JOIN A GROUP</span><strong>Slave</strong><p>Master 또는 기존 Slave의 주소로 가입합니다.<br>Slave 번호는 Master가 자동으로 결정합니다.</p></button></div>
<form id="cluster-master-form" class="cluster-form" hidden><div class="form-grid"><label>클러스터 이름<input name="name" required maxlength="80" placeholder="예: Seoul SOC"></label><label>이 장비의 관리 주소<input name="address" type="url" required placeholder="https://siem-master.example:8443"></label></div><label>이 장비의 SHA256 인증서 지문 (공인 CA 인증서는 생략 가능)<input name="certificate_pin" maxlength="95" spellcheck="false" autocomplete="off"></label><label>클러스터 가입 암호 · 16자 이상<input name="password" type="password" minlength="16" maxlength="128" required autocomplete="new-password"></label><p>관리 주소는 다른 장비에서 접근 가능해야 합니다. 원격 연결은 HTTPS가 필요합니다. 암호는 가입할 장비 관리자에게 안전하게 전달하세요.</p><button class="primary">Master로 그룹 생성 ↗</button></form>
<form id="cluster-join-form" class="cluster-form" hidden><div class="form-grid"><label>연결할 Master 또는 Slave 주소<input name="peer" type="url" required placeholder="https://siem-slave1.example:8443"></label><label>이 장비의 관리 주소<input name="address" type="url" required placeholder="https://siem-slave2.example:8443"></label></div><div class="form-grid"><label>연결 대상의 SHA256 인증서 지문 (공인 CA는 생략 가능)<input name="peer_pin" maxlength="95" spellcheck="false" autocomplete="off"></label><label>이 장비의 SHA256 인증서 지문<input name="certificate_pin" maxlength="95" spellcheck="false" autocomplete="off"></label></div><label>Master에서 설정한 클러스터 가입 암호<input name="password" type="password" minlength="16" maxlength="128" required autocomplete="off"></label><p>기존 Slave를 통해 가입해도 최종 배정은 Master가 수행합니다. Master에 연결할 수 없으면 가입을 중단하며 임의 번호를 만들지 않습니다. 현재 장비의 로컬 로그와 계정은 보존됩니다.</p><button class="primary">Slave로 가입 요청 ↗</button></form></article>
<article id="cluster-detail"></article>
<article id="cluster-journal" hidden></article>
<article><p class="signal-kicker">FAIL CLOSED. NOT SPLIT BRAIN.</p><h2>역할과 복구의 경계</h2><p>Master/Slave 번호는 가입 순서이며, 자동 장애 전환 우선순위가 아닙니다. Master 장애 시 Slave가 독자적으로 Master를 선언하지 않습니다. 가입 구성원 목록은 접속 가능하거나 로그가 동기화되었다는 증명이 아닙니다.</p><p>기존 외부 NATS 복제 배포는 별도 데이터 경로입니다. 자동 브로커 구성, 기존 데이터 시딩, 장비 교체·승격은 아직 이 가입 흐름에 통합되지 않았습니다.</p></article>`;

function chooseClusterRole(role) {
    for (const value of ["master", "slave"]) {
        const selected = value === role;
        const button = $("#choose-" + value);
        button.classList.toggle("selected", selected);
        button.setAttribute("aria-pressed", String(selected));
    }
    $("#cluster-master-form").hidden = role !== "master";
    $("#cluster-join-form").hidden = role !== "slave";
    const form = $(role === "master" ? "#cluster-master-form" : "#cluster-join-form");
    if (!form.elements.address.value) form.elements.address.value = window.location.origin;
    form.querySelector("input").focus();
}
$("#choose-master").onclick = () => chooseClusterRole("master");
$("#choose-slave").onclick = () => chooseClusterRole("slave");

clusterView = async function () {
    const permitted = me.role === "admin" && me.tenant === "default" && !me.must_change;
    $("#cluster-access").hidden = permitted;
    $("#cluster-access").textContent = "장비 가입 관리는 default 테넌트의 관리자에게만 허용됩니다.";
    for (const id of ["cluster-metrics", "cluster-data-warning", "cluster-detail"]) $("#" + id).hidden = !permitted;
    $("#cluster-enrollment").hidden = true;
    $("#cluster-journal").hidden = true;
    if (!permitted) return;
    const [c, h] = await Promise.all([api("/api/cluster"), api("/api/health")]);
    metrics("#cluster-metrics", [
        ["이 장비 역할", c.role, c.node_id.slice(0, 8)],
        ["가입된 장비", c.members.length || 1, "연결 가용성·복제 완료를 의미하지 않음"],
        ["제품 버전", c.version, "정확히 같은 버전만 가입"],
        ["로그 자동 복제", c.data_replication_ready ? "준비됨" : "미연결", "장비 가입과 별도 데이터 경로"]
    ]);
    $("#cluster-enrollment").hidden = c.mode !== "standalone";
    $("#cluster-detail").innerHTML = c.mode === "standalone"
        ? '<h2>독립 장비로 실행 중입니다.</h2><p>Master를 선택해 그룹을 만들거나, Slave를 선택해 기존 장비에 연결하세요. 가입만으로 현재 데이터가 교체되거나 공유되지 않습니다.</p>'
        : `<div class="signal-topline"><div><p class="signal-kicker">ENROLLED TOPOLOGY</p><h2>${escapeHtml(c.name || "연결된 장비 그룹")}</h2></div><span class="cluster-role">${escapeHtml(c.role)}</span></div><p>Master: <code>${escapeHtml(c.master_url)}</code></p><p>그룹 ID: <code>${escapeHtml(c.group_id)}</code>${c.membership_last_sync ? " · 가입 목록 확인: " + escapeHtml(date(c.membership_last_sync)) : ""}</p><div class="cluster-topology">${c.members.map(m => `<div class="cluster-node ${m.ordinal === 0 ? "master" : ""}"><strong>${m.ordinal === 0 ? "Master" : "Slave " + m.ordinal}</strong><small>${escapeHtml(m.url)}</small><small>${m.node_id === c.node_id ? "현재 장비 · " : ""}가입 등록됨 · v${escapeHtml(m.version)}</small></div>`).join('<span class="cluster-arrow" aria-hidden="true">↔</span>')}</div><p>이 목록은 가입 기록입니다. 장비 온라인 상태와 데이터 동기화 상태는 별도로 확인해야 합니다.</p>`;
    if (h.cluster) {
        const r = h.cluster;
        $("#cluster-journal").hidden = false;
        $("#cluster-journal").innerHTML = `<h2>별도 구성된 복제 저널</h2><p>복제 수 ${fmt(r.replicas)} · 적용 시퀀스 ${fmt(r.applied_sequence)} · 마지막 재생 ${escapeHtml(date(r.last_sync))}</p><p>${escapeHtml(r.error || "현재 재생 오류 없음")}</p><p>이 저널이 장비 가입 그룹과 자동으로 결합된 것은 아닙니다.</p>`;
    }
};
$("#cluster-refresh").onclick = async () => {
    const button = $("#cluster-refresh");
    button.disabled = true;
    try { await post("/api/cluster/refresh", {}); await clusterView(); notice("가입 상태를 확인했습니다."); }
    catch (error) { notice(error.message + " · 기존 가입 기록은 유지됩니다."); }
    finally { button.disabled = false; }
};
for (const [id, endpoint] of [["cluster-master-form", "master"], ["cluster-join-form", "join"]]) {
    $("#" + id).onsubmit = async event => {
        event.preventDefault();
        const form = event.target, button = form.querySelector("button");
        button.disabled = true;
        notice("");
        try {
            const result = await post("/api/cluster/" + endpoint, Object.fromEntries(new FormData(form)));
            form.reset();
            await clusterView();
            notice(result.role + " 가입 구성이 저장되었습니다. 로그 자동 복제는 아직 활성화되지 않았습니다.");
        } catch (error) { notice(error.message); }
        finally { form.elements.password.value = ""; button.disabled = false; }
    };
}

const appliancePreviousView = view;
view = async function(name) {
    if (me?.must_change) name = "account";
    await appliancePreviousView(name);
};
