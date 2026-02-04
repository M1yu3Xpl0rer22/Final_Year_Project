// theme-toggle.js

// 1. On Load: Check localStorage and apply theme
window.addEventListener("DOMContentLoaded", () => {
  const savedTheme = localStorage.getItem("theme");
  // Default to light mode if nothing saved, or respect saved 'dark'
  if (savedTheme === "dark") {
    document.body.classList.add("dark");
  }
  updateButtonText();
});

// 2. Toggle Function (to be called by button)
function toggleTheme() {
  document.body.classList.toggle("dark");

  // Save preference
  const isDark = document.body.classList.contains("dark");
  localStorage.setItem("theme", isDark ? "dark" : "light");

  updateButtonText();
}

// 3. Helper to update button text
function updateButtonText() {
  const btn = document.querySelector(".theme-toggle");
  if (btn) {
    const isDark = document.body.classList.contains("dark");
    // If dark mode is active, show Sun (to switch to light)
    // If light mode is active, show Moon (to switch to dark)
    btn.textContent = isDark ? "☀️" : "🌙";
  }
}


