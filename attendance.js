(() => {
    "use strict";

    const dashboardPages = {
        student: "StudentDashboard.html",
        staff: "StaffDashboard.html",
        admin: "AdminDashboard.html"
    };
    const attendanceStatuses = ["Present", "Late", "Absent"];
    const today = new Date();
    const elements = {
        navStatus: document.getElementById("navStatus"),
        dashboardLink: document.getElementById("dashboardLink"),
        recordsLink: document.getElementById("recordsLink"),
        attendanceDate: document.getElementById("attendanceDate"),
        attendanceTitle: document.getElementById("attendanceTitle"),
        attendanceMessage: document.getElementById("attendanceMessage"),
        attendanceList: document.getElementById("attendanceList"),
        logoutLink: document.getElementById("logoutLink")
    };

    let user = null;
    let todaySubjects = [];
    let attendanceRecords = {};

    function readUser() {
        try {
            const savedUser = JSON.parse(localStorage.getItem("user"));
            return savedUser && typeof savedUser === "object" ? savedUser : null;
        } catch (error) {
            return null;
        }
    }

    async function requestJson(url, options) {
        let response;
        try {
            response = await fetch(url, options);
        } catch (error) {
            throw new Error(
                "Cannot connect to the Flask server. Start it with .\\.venv\\Scripts\\python.exe app.py, then open http://127.0.0.1:5000/Attendance.html."
            );
        }

        const contentType = response.headers.get("content-type") || "";
        if (!contentType.toLowerCase().includes("application/json")) {
            throw new Error(
                `The API returned a web page instead of JSON (HTTP ${response.status}). ` +
                "Start Flask with .\\.venv\\Scripts\\python.exe app.py and open " +
                "http://127.0.0.1:5000/Attendance.html."
            );
        }

        let result;
        try {
            result = await response.json();
        } catch (error) {
            throw new Error("The Flask API returned invalid JSON. Check the Flask terminal for errors.");
        }

        if (!response.ok || !result.success) {
            throw new Error(result.message || `The request failed (HTTP ${response.status}).`);
        }
        return result;
    }

    function initializePage() {
        user = readUser();
        if (!user) {
            location.href = "index.html";
            return;
        }
        if (!Object.hasOwn(dashboardPages, user.role)) {
            location.href = "index.html";
            return;
        }

        const accountStatus = user.accountStatus || "Active";
        elements.navStatus.textContent = `Status: ${accountStatus}`;
        elements.navStatus.classList.add(accountStatus === "Active" ? "active" : "inactive");
        elements.dashboardLink.href = dashboardPages[user.role];
        elements.recordsLink.hidden = !["staff", "admin"].includes(user.role);
        elements.attendanceDate.textContent = today.toLocaleDateString(undefined, {
            weekday: "long",
            month: "long",
            day: "numeric"
        });

        if (user.role === "student") {
            loadStudentAttendance();
            return;
        }

        elements.attendanceTitle.textContent = "Today's Subject Attendance";
        loadAdminAttendance();
    }

    async function loadStudentAttendance() {
        try {
            const email = encodeURIComponent(user.email);
            const [subjectsResult, attendanceResult] = await Promise.all([
                requestJson(`/api/subjects?email=${email}`),
                requestJson(`/api/subject-attendance?email=${email}`)
            ]);

            todaySubjects = subjectsResult.subjects
                .filter(subject => subject.dayOfWeek === today.getDay())
                .map(subject => ({ subject: subject.name, time: subject.startTime }));
            attendanceRecords = Object.fromEntries(
                attendanceResult.records.map(record => [record.subject, record.status])
            );
            renderStudentAttendance();
        } catch (error) {
            showError(error);
        }
    }

    function renderStudentAttendance() {
        elements.attendanceList.replaceChildren();

        if (!todaySubjects.length) {
            elements.attendanceMessage.textContent = "No subjects are scheduled today.";
            return;
        }
        elements.attendanceMessage.textContent = "Choose your attendance for each scheduled subject.";

        todaySubjects.forEach(subject => {
            const row = document.createElement("div");
            row.className = "user-row subject-attendance-row";

            const details = document.createElement("div");
            const name = document.createElement("strong");
            const status = document.createElement("span");
            name.textContent = subject.subject;
            status.textContent =
                `${subject.time} | ${attendanceRecords[subject.subject] || "Not marked"}`;
            details.append(name, document.createElement("br"), status);

            const buttons = document.createElement("div");
            buttons.className = "attendance-buttons";
            attendanceStatuses.forEach(value => {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "edit-button";
                button.textContent = value;
                button.addEventListener("click", () => setStudentAttendance(subject.subject, value));
                buttons.append(button);
            });

            row.append(details, buttons);
            elements.attendanceList.append(row);
        });
    }

    async function setStudentAttendance(subject, status) {
        try {
            const result = await requestJson("/api/subject-attendance", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: user.email, subject, status })
            });
            attendanceRecords[subject] = result.status;
            renderStudentAttendance();
        } catch (error) {
            alert(getErrorMessage(error, "Unable to update attendance."));
        }
    }

    async function loadAdminAttendance() {
        try {
            const result = await requestJson(
                `/api/admin/subject-attendance?adminEmail=${encodeURIComponent(user.email)}`
            );
            renderAdminAttendance(result.records);
        } catch (error) {
            showError(error);
        }
    }

    function renderAdminAttendance(records) {
        elements.attendanceList.replaceChildren();
        if (!records.length) {
            elements.attendanceMessage.textContent = "No subject attendance has been marked today.";
            return;
        }

        elements.attendanceMessage.textContent = "";
        records.forEach(record => {
            const row = document.createElement("div");
            row.className = "user-row";

            const details = document.createElement("div");
            const name = document.createElement("strong");
            const status = document.createElement("span");
            name.textContent = `${record.first_name} ${record.last_name} - ${record.subject}`;
            status.textContent = record.status;
            details.append(name, document.createElement("br"), status);

            const select = document.createElement("select");
            select.setAttribute("aria-label", `Attendance for ${record.first_name} ${record.last_name}`);
            attendanceStatuses.forEach(value => {
                select.add(new Option(value, value, false, value === record.status));
            });
            select.addEventListener("change", () => updateAdminAttendance(record, select.value));

            row.append(details, select);
            elements.attendanceList.append(row);
        });
    }

    async function updateAdminAttendance(record, status) {
        try {
            await requestJson("/api/admin/subject-attendance", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    adminEmail: user.email,
                    email: record.email,
                    subject: record.subject,
                    status
                })
            });
            await loadAdminAttendance();
        } catch (error) {
            alert(getErrorMessage(error, "Unable to update attendance."));
        }
    }

    function showError(error) {
        elements.attendanceMessage.textContent = getErrorMessage(error, "Unable to load attendance.");
    }

    function getErrorMessage(error, fallback) {
        return error instanceof Error ? error.message : fallback;
    }

    function logout() {
        localStorage.removeItem("user");
        location.href = "index.html";
    }

    elements.logoutLink.addEventListener("click", event => {
        event.preventDefault();
        logout();
    });

    initializePage();
})();
