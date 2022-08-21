const sensitiveEl = document.getElementById("sensitive");

// Check for token in session storage
function getToken() {
  const token = sessionStorage.getItem("token")
  if (!token) {
    // if does not exist redirect to login page
    console.log("token is null");
    location = "/login";
  }
  return token;
}

// Send request for sensitive information using token
function getSensitiveInfo(token) {
  console.log("Getting sensitive info");
  const response = fetch("/api/protected", {
    headers: {
      "Authorization": `Bearer ${token}`,
    },
  })
    .then((response) => {
      if (response.status === 200) {
        response.json()
      } else {
        sessionStorage.removeItem("token");
        location = "/login"
      }
    })
    .then((data) => {
      writeSecretData(data);
    })
    .catch((error) => {
      // If error in response redirect to login page
      console.error("Error: ", error);
      location = "/login"
    });
}

// Show sensitive information
function writeSecretData(data) {
  sensitiveEl.insertAdjacentHTML("beforeend", '<span class="shhhh"><p>This is the sensitive info</p></span>')
}

const token = getToken();
getSensitiveInfo(token);
