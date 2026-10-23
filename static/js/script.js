// static/js/script.js
document.addEventListener('DOMContentLoaded', function() {
    // Only load charts on the dashboard and reports pages
    if (document.getElementById('alertsByTypeChart') || document.getElementById('alertsBySeverityChart')) {
        loadChartData();
    }
});

function loadChartData() {
    // Chart for Alerts by Type
    fetch('/api/alert_counts_by_type')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('alertsByTypeChart');
            if (ctx) {
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: '# of Alerts by Type',
                            data: data.values,
                            backgroundColor: [
                                'rgba(255, 99, 132, 0.7)',
                                'rgba(54, 162, 235, 0.7)',
                                'rgba(255, 206, 86, 0.7)',
                                'rgba(75, 192, 192, 0.7)',
                                'rgba(153, 102, 255, 0.7)',
                                'rgba(255, 159, 64, 0.7)'
                            ],
                            borderColor: [
                                'rgba(255, 99, 132, 1)',
                                'rgba(54, 162, 235, 1)',
                                'rgba(255, 206, 86, 1)',
                                'rgba(75, 192, 192, 1)',
                                'rgba(153, 102, 255, 1)',
                                'rgba(255, 159, 64, 1)'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        },
                        plugins: {
                            title: {
                                display: true,
                                text: 'Total Alerts by Type'
                            }
                        }
                    }
                });
            }
        })
        .catch(error => console.error('Error fetching alerts by type data:', error));

    // Chart for Alerts by Severity
    fetch('/api/alert_counts_by_severity')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('alertsBySeverityChart');
            if (ctx) {
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: '# of Alerts by Severity',
                            data: data.values,
                            backgroundColor: [
                                'rgba(220, 53, 69, 0.7)', // Critical
                                'rgba(255, 193, 7, 0.7)',  // High
                                'rgba(253, 126, 20, 0.7)', // Medium
                                'rgba(40, 167, 69, 0.7)'   // Low
                            ],
                            borderColor: [
                                'rgba(220, 53, 69, 1)',
                                'rgba(255, 193, 7, 1)',
                                'rgba(253, 126, 20, 1)',
                                'rgba(40, 167, 69, 1)'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Alerts by Severity'
                            }
                        }
                    }
                });
            }
        })
        .catch(error => console.error('Error fetching alerts by severity data:', error));
}