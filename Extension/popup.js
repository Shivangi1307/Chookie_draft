document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("scanCookies");
  const tbody = document.querySelector("#cookieTable tbody");
  const resultDiv = document.getElementById("result");

  const scoreContainer = document.getElementById("scoreMeterContainer");
  const scoreBarInner = document.getElementById("scoreBarInner");
  const scoreValue = document.getElementById("scoreValue");
  const toggleBtn = document.getElementById("toggleTableBtn");
  const table = document.getElementById("cookieTable");

  function escapeHtml(str) {
    return str.replace(/[&<>"']/g, m => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
    }[m]));
  }

  function sameSiteDisplay(raw) {
    switch(raw) {
      case "no_restriction": return "None";
      case "none": return "None";
      case "lax": return "Lax";
      case "strict": return "Strict";
      default: return "Unspecified";
    }
  }

  // Hide/show table only when user clicks button
  toggleBtn.addEventListener("click", () => {
    if (table.style.display === "none") {
      table.style.display = "table";
      toggleBtn.innerText = "Hide Cookie Table";
    } else {
      table.style.display = "none";
      toggleBtn.innerText = "Show Cookie Table";
    }
  });

  scanBtn.addEventListener("click", () => {
    resultDiv.innerHTML = "Scanning cookies…";
    chrome.runtime.sendMessage({ action: "getCookies" }, (response) => {

      if (!response) {
        resultDiv.innerHTML = "No response from background.";
        return;
      }
      if (response.error) {
        resultDiv.innerHTML = "Error: " + response.error;
        return;
      }

      const pairs = response.cookies || [];
      tbody.innerHTML = "";

      let totalScore = 0;

      // Build table
      pairs.forEach(pair => {
        const c = pair.cookie;
        const r = pair.result;

        totalScore += r.score;

        const ss = sameSiteDisplay(c.sameSite || c.same_site || "unspecified");

        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${escapeHtml(c.name)}</td>
          <td style="text-align:center">${c.secure ? "✓" : "✗"}</td>
          <td style="text-align:center">${c.httpOnly ? "✓" : "✗"}</td>
          <td>${ss}</td>
          <td style="text-align:center">${r.score}</td>
          <td>${r.classification}</td>
        `;

        tbody.appendChild(row);
      });

      // Score meter visible only after scan
      scoreContainer.style.display = "block";
      scoreBarInner.style.width = Math.min(totalScore, 100) + "%";

      // Bar color based on severity
      if (totalScore > 50) scoreBarInner.style.background = "red";
      else if (totalScore > 20) scoreBarInner.style.background = "orange";
      else scoreBarInner.style.background = "green";

      scoreValue.innerHTML = `Total Score: ${totalScore}`;

      resultDiv.innerHTML = `Scan completed. Found ${pairs.length} cookies.`;
    });
  });
});
document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("scanCookies");
  const tbody = document.querySelector("#cookieTable tbody");
  const resultDiv = document.getElementById("result");

  const scoreContainer = document.getElementById("scoreMeterContainer");
  const scoreBarInner = document.getElementById("scoreBarInner");
  const scoreValue = document.getElementById("scoreValue");
  const toggleBtn = document.getElementById("toggleTableBtn");
  const table = document.getElementById("cookieTable");

  function escapeHtml(str) {
    return str.replace(/[&<>"']/g, m => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
    }[m]));
  }

  function sameSiteDisplay(raw) {
    switch(raw) {
      case "no_restriction": return "None";
      case "none": return "None";
      case "lax": return "Lax";
      case "strict": return "Strict";
      default: return "Unspecified";
    }
  }

  // Hide/show table only when user clicks button
  toggleBtn.addEventListener("click", () => {
    if (table.style.display === "none") {
      table.style.display = "table";
      toggleBtn.innerText = "Hide Cookie Table";
    } else {
      table.style.display = "none";
      toggleBtn.innerText = "Show Cookie Table";
    }
  });

//   scanBtn.addEventListener("click", () => {
//     resultDiv.innerHTML = "Scanning cookies…";
//     chrome.runtime.sendMessage({ action: "getCookies" }, (response) => {

//       if (!response) {
//         resultDiv.innerHTML = "No response from background.";
//         return;
//       }
//       if (response.error) {
//         resultDiv.innerHTML = "Error: " + response.error;
//         return;
//       }

//       const pairs = response.cookies || [];
//       tbody.innerHTML = "";

//       let totalScore = 0;

//       // Build table
//       pairs.forEach(pair => {
//         const c = pair.cookie;
//         const r = pair.result;

//         totalScore += r.score;

//         const ss = sameSiteDisplay(c.sameSite || c.same_site || "unspecified");

//         const row = document.createElement("tr");
//         row.innerHTML = `
//           <td>${escapeHtml(c.name)}</td>
//           <td style="text-align:center">${c.secure ? "&#10003;" : "&#10007;"}</td>
//           <td style="text-align:center">${c.httpOnly ? "&#10003;" : "&#10007;"}</td>
//           <td>${ss}</td>
//           <td style="text-align:center">${r.score}</td>
//           <td>${r.classification}</td>
//         `;

//         tbody.appendChild(row);
//       });

//       // Score meter visible only after scan
//       scoreContainer.style.display = "block";
//       scoreBarInner.style.width = Math.min(totalScore, 100) + "%";

//       // Bar color based on severity
//       if (totalScore > 50) scoreBarInner.style.background = "red";
//       else if (totalScore > 20) scoreBarInner.style.background = "orange";
//       else scoreBarInner.style.background = "green";

//       scoreValue.innerHTML = `Total Score: ${totalScore}`;

//       resultDiv.innerHTML = `Scan completed. Found ${pairs.length} cookies.`;
//     });
//   });
// });
scanBtn.addEventListener("click", () => {
  resultDiv.innerHTML = "Scanning cookies…";
  chrome.runtime.sendMessage({ action: "getCookies" }, (response) => {

    if (!response) {
      resultDiv.innerHTML = "No response from background.";
      return;
    }
    if (response.error) {
      resultDiv.innerHTML = "Error: " + response.error;
      return;
    }

    const pairs = response.cookies || [];
    tbody.innerHTML = "";

    let totalScore = 0;

    // Build table
    pairs.forEach(pair => {
      const c = pair.cookie;
      const r = pair.result;

      totalScore += r.score;

      const ss = sameSiteDisplay(c.sameSite || c.same_site || "unspecified");

      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${escapeHtml(c.name)}</td>
        <td style="text-align:center">${c.secure ? "&#10003;" : "&#10007;"}</td>
        <td style="text-align:center">${c.httpOnly ? "&#10003;" : "&#10007;"}</td>
        <td>${ss}</td>
        <td style="text-align:center">${r.score}</td>
        <td>${r.classification}</td>
      `;

      tbody.appendChild(row);
    });

    // ⭐ NEW: Calculate average score
    const avgScore = pairs.length > 0 ? (totalScore / pairs.length) : 0;

    // Score meter visible only after scan
    scoreContainer.style.display = "block";
    scoreBarInner.style.width = Math.min(avgScore, 100) + "%";

    // Bar color based on severity (based on avg)
    if (avgScore > 50) scoreBarInner.style.background = "red";
    else if (avgScore > 20) scoreBarInner.style.background = "orange";
    else scoreBarInner.style.background = "green";

    // Show AVG, not total
    scoreValue.innerHTML = `Average Score: ${avgScore.toFixed(2)}`;

    resultDiv.innerHTML = `Scan completed. Found ${pairs.length} cookies.`;
  });
});
});


