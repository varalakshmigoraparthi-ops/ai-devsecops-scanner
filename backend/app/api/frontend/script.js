const fileInput = document.getElementById("fileInput");
const scanButton = document.getElementById("scanButton");

const fileName = document.getElementById("fileName");
const status = document.getElementById("status");

const summary = document.getElementById("summary");
const results = document.getElementById("results");

const totalFindings = document.getElementById("totalFindings");
const criticalFindings = document.getElementById("criticalFindings");
const highFindings = document.getElementById("highFindings");
const mediumFindings = document.getElementById("mediumFindings");

const findingsContainer = document.getElementById("findingsContainer");


// File selection
fileInput.addEventListener("change", () => {

    if (fileInput.files.length > 0) {

        fileName.textContent =
            "Selected file: " + fileInput.files[0].name;

        status.textContent = "";
    }
});


// Scan button
scanButton.addEventListener("click", async (event) => {

    // Prevent page refresh / form submission
    event.preventDefault();

    if (fileInput.files.length === 0) {

        status.textContent =
            "Please select a Python file first.";

        return;
    }


    const file = fileInput.files[0];


    if (!file.name.endsWith(".py")) {

        status.textContent =
            "Only Python (.py) files are supported.";

        return;
    }


    const formData = new FormData();

    formData.append("file", file);


    status.textContent = "Scanning file...";

    scanButton.disabled = true;


    try {

        const response = await fetch(
            "http://127.0.0.1:8000/scan-file",
            {
                method: "POST",
                body: formData
            }
        );


        if (!response.ok) {
            throw new Error("Server error");
        }


        const data = await response.json();

        console.log("SCAN API RESPONSE:", data);


        displayResults(data);


        status.textContent =
            "Scan completed successfully.";


    } catch (error) {

        console.error(error);

        status.textContent =
            "Unable to connect to the scanner server.";
    }


    scanButton.disabled = false;
});


// Display scan results
function displayResults(data) {

    summary.classList.remove("hidden");

    results.classList.remove("hidden");


    const findings = data.findings || [];


    // Total findings
    totalFindings.textContent =
        findings.length;


    let critical = 0;
    let high = 0;
    let medium = 0;


    // Count severity
    findings.forEach(finding => {

        if (finding.severity === "CRITICAL") {

            critical++;

        } else if (finding.severity === "HIGH") {

            high++;

        } else if (finding.severity === "MEDIUM") {

            medium++;
        }

    });


    criticalFindings.textContent = critical;

    highFindings.textContent = high;

    mediumFindings.textContent = medium;


    // Clear previous results
    findingsContainer.innerHTML = "";


    // No vulnerabilities
    if (findings.length === 0) {

        findingsContainer.innerHTML = `
            <div class="finding">
                <h3>No vulnerabilities found 🎉</h3>

                <p>
                    Your code passed the current security checks.
                </p>
            </div>
        `;

        return;
    }


    // Display vulnerabilities
    findings.forEach(finding => {

        const severityClass =
            finding.severity.toLowerCase();


        const findingCard =
            document.createElement("div");


        findingCard.className = "finding";


        findingCard.innerHTML = `
            <h3>
                ${escapeHtml(finding.type)}
            </h3>

            <p>
                <strong>Severity:</strong>

                <span class="severity ${severityClass}">
                    ${escapeHtml(finding.severity)}
                </span>
            </p>

            <p>
                <strong>CWE:</strong>
                ${escapeHtml(finding.cwe)}
            </p>

            <p>
                <strong>Line:</strong>
                ${escapeHtml(String(finding.line))}
            </p>

            <p>
                <strong>Why is it vulnerable?</strong><br>

                ${escapeHtml(finding.why)}
            </p>

            <p>
                <strong>Risk:</strong><br>

                ${escapeHtml(finding.risk)}
            </p>

            <p>
                <strong>Recommendation:</strong><br>

                ${escapeHtml(finding.recommendation)}
            </p>
        `;


        findingsContainer.appendChild(findingCard);

    });
}


// HTML escaping for security
function escapeHtml(value) {

    const div =
        document.createElement("div");

    div.textContent = value;

    return div.innerHTML;
}


// Load scan history
async function loadScanHistory() {

    const historyContainer =
        document.getElementById("historyContainer");


    try {

        const response = await fetch(
            "http://127.0.0.1:8000/scan-history"
        );


        if (!response.ok) {

            throw new Error(
                "Unable to load history"
            );
        }


        const data =
            await response.json();


        historyContainer.innerHTML = "";


        if (data.history.length === 0) {

            historyContainer.innerHTML =
                "<p>No previous scans found.</p>";

            return;
        }


        data.history.forEach(item => {

            const historyCard =
                document.createElement("div");


            historyCard.className =
                "finding";


            const severityClass =
                item.severity.toLowerCase();


            historyCard.innerHTML = `
                <h3>
                    ${escapeHtml(item.vulnerability_type)}
                </h3>

                <p>
                    <strong>File:</strong>

                    ${escapeHtml(item.filename)}
                </p>

                <p>
                    <strong>Severity:</strong>

                    <span class="severity ${severityClass}">
                        ${escapeHtml(item.severity)}
                    </span>
                </p>

                <p>
                    <strong>CWE:</strong>

                    ${escapeHtml(item.cwe)}
                </p>

                <p>
                    <strong>Line:</strong>

                    ${escapeHtml(String(item.line))}
                </p>

                <p>
                    <strong>Recommendation:</strong><br>

                    ${escapeHtml(item.recommendation)}
                </p>
            `;


            historyContainer.appendChild(
                historyCard
            );

        });


    } catch (error) {

        console.error(error);


        historyContainer.innerHTML =
            "<p>Unable to load scan history.</p>";
    }
}


async function loadDashboard() {
    try {
        const response = await fetch("http://127.0.0.1:8000/dashboard");

        if (!response.ok) {
            throw new Error("Failed to load dashboard");
        }

        const data = await response.json();

        document.getElementById("dashboardTotal").textContent =
            data.total_vulnerabilities;

        document.getElementById("dashboardCritical").textContent =
            data.severity_counts.CRITICAL;

        document.getElementById("dashboardHigh").textContent =
            data.severity_counts.HIGH;

        document.getElementById("dashboardMedium").textContent =
            data.severity_counts.MEDIUM;

        const distribution =
            document.getElementById("vulnerabilityDistribution");

        distribution.innerHTML = "";
const vulnerabilityCounts = data.vulnerability_counts;
const maxCount = Math.max(...Object.values(vulnerabilityCounts), 1);

for (const [type, count] of Object.entries(vulnerabilityCounts)) {
    const item = document.createElement("div");
    item.className = "dashboard-bar";

    const label = document.createElement("div");
    label.className = "dashboard-bar-label";

    const typeLabel = document.createElement("span");
    typeLabel.textContent = type;

    const countLabel = document.createElement("span");
    countLabel.textContent = count;

    label.appendChild(typeLabel);
    label.appendChild(countLabel);

    const track = document.createElement("div");
    track.className = "dashboard-bar-track";

    const fill = document.createElement("div");
    fill.className = "dashboard-bar-fill";
    fill.style.width = `${(count / maxCount) * 100}%`;

    track.appendChild(fill);
    item.appendChild(label);
    item.appendChild(track);

    distribution.appendChild(item);
}
        
    } catch (error) {
        console.error("Dashboard error:", error);
    }
}

loadDashboard();