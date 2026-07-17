// CyberPhish - small UX helpers

document.addEventListener("DOMContentLoaded", () => {
  // Auto-dismiss flash messages after 6 seconds
  document.querySelectorAll(".flash").forEach((el) => {
    setTimeout(() => {
      el.style.transition = "opacity 0.4s ease";
      el.style.opacity = "0";
      setTimeout(() => el.remove(), 400);
    }, 6000);
  });

  // Upload page: show selected filename
  const fileInput = document.getElementById("csv_file");
  const fileLabel = document.getElementById("file_name_display");
  if (fileInput && fileLabel) {
    fileInput.addEventListener("change", () => {
      fileLabel.textContent = fileInput.files.length
        ? `Selected: ${fileInput.files[0].name}`
        : "";
    });
  }
});
