let toggle = document.getElementById("hideshow");
let isShow = false;
let password = document.getElementById("pass");
toggle.addEventListener("click", () =>{
  if (isShow === false) {
    toggle.innerHTML = "hide";
    isShow = true
    password.setAttribute("type", "text")
  }else {
    isShow = false;
    toggle.innerHTML = "show"
    password.setAttribute("type", "password");
  }
})
