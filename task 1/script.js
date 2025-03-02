let users = [
  { username: "user0", password: "XyZaB" },
  { username: "user1", password: "aaaae" },
];

let submitBtn = document.querySelector("[type='submit']");
let username = document.querySelector("[name='username']");
let password = document.querySelector("[name='password']");

submitBtn.onclick = function (e) {
  e.preventDefault();

  let p = document.querySelector(".failed");
  let loginSuccess = false;

  for (let i = 0; i < users.length; i++) {
    if (
      username.value === users[i].username &&
      password.value === users[i].password
    ) {
      p?.remove();
      localStorage.setItem("loggedInUser", username.value);
      window.location.href = "welcome.html";
      loginSuccess = true;
      break;
    }
  }

  if (!loginSuccess) {
    if (!document.querySelector(".failed")) {
      failedLogin();
    }
  }

  console.log(username.value, password.value);
};

function failedLogin() {
  let p = document.createElement("p");
  p.textContent = "Username or password is wrong";
  p.style.color = "red";
  p.className = "failed";
  document.forms[0].append(p);
}
