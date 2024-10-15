let fst = document.getElementById("click1");
let scd = document.getElementById("click2");
let trd = document.getElementById("click3");
let frt = document.getElementById("click4");
let notify = document.getElementById("notify");
let darkmode = document.getElementById("darkmode");

        
fst.addEventListener("click", () =>{
  let element = document.createElement("a");
  element.setAttribute("href", "/home");
  element.click();
});
scd.addEventListener("click", () =>{
  let element = document.createElement("a");
  element.setAttribute("href", "/history");
  element.click();
});
trd.addEventListener("click", () =>{
  let element = document.createElement("a");
  element.setAttribute("href", "/notification");
  element.click();
});
frt.addEventListener("click", () =>{
  let element = document.createElement("a");
  element.setAttribute("href", "/logout");
  element.click();
});

notify.addEventListener("click", () => {
  let toGo = document.createElement("a");
  toGo.setAttribute("href", "/notification");
  toGo.click();
})

darkmode.addEventListener("click", () =>{
  let mode = document.createElement("a");
  mode.setAttribute("href", "/nightmode");
  mode.click();
})