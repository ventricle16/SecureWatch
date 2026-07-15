/*
==================================================
SecureWatch SIEM Dashboard JS
Author: Niloy Sarkar
==================================================
*/

document.addEventListener("DOMContentLoaded", () => {

    initializeCounters();
    initializeFileUpload();
    initializeClock();
    initializeAutoRefresh();

});

/* ==========================================
   Animated Statistic Counters
========================================== */

function initializeCounters() {

    const counters = document.querySelectorAll(".display-4");

    counters.forEach(counter => {

        const target = parseInt(counter.innerText) || 0;

        let count = 0;

        const speed = 25;

        const updateCounter = () => {

            if (count < target) {

                count++;

                counter.innerText = count;

                setTimeout(updateCounter, speed);

            } else {

                counter.innerText = target;
            }
        };

        updateCounter();
    });
}

/* ==========================================
   File Upload Display
========================================== */

function initializeFileUpload() {

    const fileInput = document.querySelector('input[type="file"]');

    if (!fileInput) return;

    fileInput.addEventListener("change", function () {

        if (this.files.length > 0) {

            console.log(
                "Selected file:",
                this.files[0].name
            );

        }
    });
}

/* ==========================================
   Real-Time Clock
========================================== */

function initializeClock() {

    const clockElement = document.getElementById("liveClock");

    if (!clockElement) return;

    function updateClock() {

        const now = new Date();

        clockElement.innerText =
            now.toLocaleDateString() +
            " | " +
            now.toLocaleTimeString();
    }

    updateClock();

    setInterval(updateClock, 1000);
}

/* ==========================================
   Dashboard Auto Refresh
========================================== */

function initializeAutoRefresh() {

    setInterval(() => {

        console.log(
            "SecureWatch: refreshing dashboard..."
        );

        window.location.reload();

    }, 10000);

}

/* ==========================================
   Alert Detection Notification
========================================== */

const currentAlerts =
    parseInt(
        document.body.dataset.alerts || 0
    );

const previousAlerts =
    localStorage.getItem("previousAlerts");

if (
    previousAlerts !== null &&
    parseInt(previousAlerts) < currentAlerts
) {

    showAlertNotification(
        currentAlerts -
        parseInt(previousAlerts)
    );
}

localStorage.setItem(
    "previousAlerts",
    currentAlerts
);

function showAlertNotification(newAlerts) {

    const notification =
        document.createElement("div");

    notification.innerHTML =
        `🚨 ${newAlerts} New Alert(s) Detected`;

    notification.style.position = "fixed";
    notification.style.top = "20px";
    notification.style.right = "20px";
    notification.style.padding = "15px 25px";
    notification.style.background = "#dc2626";
    notification.style.color = "white";
    notification.style.borderRadius = "10px";
    notification.style.fontWeight = "bold";
    notification.style.zIndex = "9999";
    notification.style.boxShadow =
        "0 0 20px rgba(255,0,0,.5)";

    document.body.appendChild(notification);

    setTimeout(() => {

        notification.remove();

    }, 5000);
}

/* ==========================================
   Chart Auto Refresh Support
========================================== */

function refreshCharts() {

    if (window.alertChart) {

        window.alertChart.update();
    }

    if (window.ipChart) {

        window.ipChart.update();
    }
}

/* ==========================================
   SOC Health Monitor
========================================== */

function updateSOCStatus() {

    const health =
        document.getElementById("soc-health");

    if (!health) return;

    health.innerHTML =
        '<span class="badge bg-success">HEALTHY</span>';
}

updateSOCStatus();