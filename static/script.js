fetch("/api/data")
.then(res => res.json())
.then(data => {

    const s = data.stats;
    const packets = data.packets;

    const suspiciousPackets = packets.filter(p => p.alert && p.alert !== "None");
    const isSafe = suspiciousPackets.length === 0;

    const root = document.documentElement;

    if (isSafe) {
        root.style.setProperty('--primary', '#22c55e');
        root.style.setProperty('--secondary', '#14532d');
        root.style.setProperty('--bg-soft', '#052e16');
    } else {
        root.style.setProperty('--primary', '#ff1a1a');
        root.style.setProperty('--secondary', '#660000');
        root.style.setProperty('--bg-soft', '#1a0000');
    }

    document.getElementById("cards").innerHTML = `
        <div class="card"><h2>${s.TCP}</h2><p>TCP</p></div>
        <div class="card"><h2>${s.UDP}</h2><p>UDP</p></div>
        <div class="card"><h2>${s.ICMP}</h2><p>ICMP</p></div>
        <div class="card"><h2>${s.Suspicious}</h2><p>Threats</p></div>
    `;

    let risk = Math.min(100, (s.Suspicious || 0) * 2);
    document.getElementById("riskValue").innerText = risk + "%";

    const primary = getComputedStyle(root).getPropertyValue('--primary');
    const secondary = getComputedStyle(root).getPropertyValue('--secondary');

    new Chart(document.getElementById("trendChart"), {
        type: "line",
        data: {
            labels: packets.map((_, i) => i),
            datasets: [{
                data: packets.map(() => Math.random() * 20),
                borderColor: primary,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false   // 🔥 KEY FIX
        }
    });

    new Chart(document.getElementById("gaugeChart"), {
        type: "doughnut",
        data: {
            datasets: [{
                data: [risk, 100 - risk],
                backgroundColor: [primary, "#111"]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            rotation: -90,
            circumference: 180,
            cutout: "70%",
            plugins: { legend: { display: false } }
        }
    });

    new Chart(document.getElementById("barChart"), {
        type: "bar",
        data: {
            labels: ["TCP", "UDP", "ICMP"],
            datasets: [{
                data: [s.TCP, s.UDP, s.ICMP],
                backgroundColor: [primary, secondary, "#333"]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });

    new Chart(document.getElementById("donutChart"), {
        type: "doughnut",
        data: {
            labels: ["Ports", "Keywords"],
            datasets: [{
                data: [s.Suspicious / 2, s.Suspicious / 2],
                backgroundColor: [primary, secondary]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });

    let rows = "";
    packets.slice(0, 100).forEach(p => {
        rows += `
        <tr>
            <td>${p.src}</td>
            <td>${p.dst}</td>
            <td>${p.protocol}</td>
            <td>${p.port || "-"}</td>
            <td>${p.size}</td>
            <td class="${p.alert !== 'None' ? 'status-bad' : 'status-ok'}">
                ${p.alert !== 'None' ? '⚠️' : 'OK'}
            </td>
        </tr>`;
    });

    document.getElementById("table").innerHTML = rows;

    let alertHTML = "";

    if (isSafe) {
        alertHTML = `<div>✔ System Secure</div>`;
    } else {
        suspiciousPackets.slice(0, 6).forEach(p => {
            alertHTML += `
            <div class="alert-item">
                ⚠️ ${p.src} → ${p.dst}<br>
                <small>${p.alert}</small>
            </div>`;
        });
    }

    document.getElementById("alerts").innerHTML = alertHTML;

})
.catch(err => console.error(err));