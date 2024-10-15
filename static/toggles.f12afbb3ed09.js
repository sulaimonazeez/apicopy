function Payvassel() {
  let payvassel = document.getElementById("payvessel");
  let monnify = document.getElementById("monnify");
  payvessel.style.display = "block";
  monnify.style.display = "none";
}

function Monnify() {
  let payvassel = document.getElementById("payvessel");
  let monnify = document.getElementById("monnify");
  payvessel.style.display = "none";
  monnify.style.display = "block";
}

function Redirect(data) {
  x = document.createElement("a");
  x.setAttribute("href", data);
  x.click();
  console.log("redirecting...")
  alert("moving")
}

$(document).ready(() => {
    $("#airtel").click(() => {
        $(".selecting").val("Airtel").change();
    });

    $("#mtn").click(() => {
        $(".selecting").val("MTN").change();
    });

    $("#glo").click(() => {
        $(".selecting").val("GLO").change();
    });

    $("#9mobile").click(() => {
        $(".selecting").val("GLO").change();
    });

    $(".close-message").click(() => {
        $(".alert").hide();
    });

    let toGo = document.createElement("a");
    $("#data").click(() => {
        toGo.setAttribute("href", "/databundle");
        toGo.click();
    });

    $("#upgrade").click(() => {
        let blur = $("#addBlur");
        blur.addClass("addBlur");
        $(".modal").show();
    });

    $(".fa-close").click(() => {
        let blur = $("#addBlur");
        blur.removeClass("addBlur");
        $(".modal").hide();
    });

    $("#myprofile").click(() => {
        toGo.setAttribute("href", "/profile");
        toGo.click();
    });

    $("#more").click(() => {
        toGo.setAttribute("href", "#");
        toGo.click();
    });
    $("#profiles").on("click", ()=>{
      $(".profiles").show();
      $(".password").hide();
      $(".pin").hide();
    });
    $("#pin").on("click", ()=>{
      $(".profiles").hide();
      $(".password").hide();
      $(".pin").show();
    })
    $("#password").on("click", ()=>{
      $(".profiles").hide();
      $(".password").show();
      $(".pin").hide();
    })
    $(".clip-bord").on("click", ()=>{
      const datas = $("#accs").attr("my-data");
      navigator.clipboard.writeText(datas);
    })
});