const apiKey = "YOUR_API_KEY_HERE";

async function scanURL() {
  const url = document.getElementById("urlInput").value;
  const resultDiv = document.getElementById("result");
  if (!url) return alert("Enter a URL");

  resultDiv.textContent = "Scanning...";

  try {
    const submitRes = await fetch("https://corsproxy.io/?https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const { data: { id } } = await submitRes.json();

    const reportRes = await fetch(`https://corsproxy.io/?https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { "x-apikey": apiKey }
    });

    const { data: { attributes: { stats } } } = await reportRes.json();
    const total = (stats.malicious || 0) + (stats.suspicious || 0);

    resultDiv.innerHTML = total > 0
      ? `❌ <span class="text-red-600">Unsafe: Detected by ${total} scanners.</span>`
      : `✅ <span class="text-green-600">Safe: No threats found.</span>`;
  } catch {
    resultDiv.textContent = "❌ Scan failed.";
  }
}

function startQRScanner() {
  const qr = new Html5Qrcode("qr-reader");
  qr.start({ facingMode: "environment" }, { fps: 10, qrbox: 250 },
    msg => {
      document.getElementById("urlInput").value = msg;
      scanURL();
      qr.stop();
    }
  );
}

startQRScanner();
