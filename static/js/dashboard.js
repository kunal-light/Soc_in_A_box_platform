/* SOC-in-a-Box - Live Dashboard Version 2 */

document.addEventListener("DOMContentLoaded", () => {
    initializeClock();
    initializeCharts();
    initializeAnimations();
});

function initializeClock() {
    const clock = document.getElementById("currentTime");
    if (!clock) return;
    const updateClock = () => {
        clock.textContent = new Date().toLocaleTimeString();
    };
    updateClock();
    setInterval(updateClock, 1000);
}

function getDashboardData() {
    const dataElement = document.getElementById("dashboard-data");
    if (!dataElement) {
        return {
            type_labels: [],
            type_values: [],
            severity_labels: [],
            severity_values: []
        };
    }

    try {
        return JSON.parse(dataElement.textContent);
    } catch (error) {
        console.error("Unable to parse dashboard data:", error);
        return {
            type_labels: [],
            type_values: [],
            severity_labels: [],
            severity_values: []
        };
    }
}

function initializeCharts() {
    if (typeof Chart === "undefined") return;

    const data = getDashboardData();
    Chart.defaults.color = "#cbd5e1";
    Chart.defaults.borderColor = "rgba(148, 163, 184, 0.15)";

    const threatCanvas = document.getElementById("threatChart");
    if (threatCanvas) {
        new Chart(threatCanvas, {
            type: "bar",
            data: {
                labels: data.severity_labels,
                datasets: [{
                    label: "IOC Count",
                    data: data.severity_values,
                    backgroundColor: [
                        "rgba(239, 68, 68, 0.75)",
                        "rgba(245, 158, 11, 0.75)",
                        "rgba(34, 197, 94, 0.75)",
                        "rgba(59, 130, 246, 0.75)"
                    ],
                    borderWidth: 0,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    }
                }
            }
        });
    }

    const iocCanvas = document.getElementById("iocChart");
    if (iocCanvas) {
        new Chart(iocCanvas, {
            type: "doughnut",
            data: {
                labels: data.type_labels,
                datasets: [{
                    data: data.type_values,
                    backgroundColor: [
                        "#3b82f6",
                        "#22c55e",
                        "#f59e0b",
                        "#ef4444",
                        "#8b5cf6",
                        "#06b6d4"
                    ],
                    borderColor: "#1e293b",
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            padding: 16,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
    }
}

function initializeAnimations() {
    document.querySelectorAll(".card").forEach((card, index) => {
        card.style.opacity = "0";
        card.style.transform = "translateY(14px)";
        setTimeout(() => {
            card.style.transition = "opacity .35s ease, transform .35s ease, box-shadow .3s ease";
            card.style.opacity = "1";
            card.style.transform = "translateY(0)";
        }, Math.min(index * 60, 500));
    });
}
