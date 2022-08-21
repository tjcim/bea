const loginForm = document.getElementById("loginForm");
const usernameEl = document.getElementById("username");
const passwordEl = document.getElementById("password")


function storeJwt(data) {
  console.log("Storing token in session storage.");
  sessionStorage.setItem('token', data.token);
}

function loginSubmit(event) {
  event.preventDefault();

  const data = {
    username: usernameEl.value,
    password: passwordEl.value,
  }

  const response = fetch("/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  })
    .then((response) => response.json())
    .then((data) => {
      storeJwt(data);
      console.log("Redirecting to protected site");
      location = "/protected";
    })
    .catch((error) => {
      console.error("Error: ", error);
    });
}

loginForm.addEventListener("submit", loginSubmit);
