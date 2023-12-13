"use strict";

function getLoginStatus(f)
{
    const result = fetch('status').then(response => response.json()).then(data => {
        if(data.login) {
            f.user = data.user;
            f.login = "Logged in as user "+data.user;
            f.loggedon = true;
        }
        else {
            f.login = "";
            f.loggedon = false;
        }
    });

    result.then( r => {
        let a = new URL(window.location.href)
        f.can_touch_image=0;
        let i = a.searchParams.get("i");
        if(i != null) {
            f.imageid = i;
            fetch('can_touch_image/'+f.imageid).then(response => {
                if (response.ok) {
                    response.json().then(data => {
                         f.can_touch_image = data.can_touch_image;
                    });
                }
            });
        }
    });
    
}

function doLogout(f)
{
    fetch("logout", {method: "POST"})
        .then(function(res){ getLoginStatus(f);});
}

function getImageList(f)
{
    fetch('all-images').then(response => response.json()).then(data => {
        f.images = data;
    });
}

function getMyImageList(f)
{
    fetch('my-images').then(response => response.json()).then(data => {
        f.images = data;
    });
}


function doLogin(el, f)
{
    const data = new URLSearchParams(new FormData(el));
    fetch("login", {method: "POST", body: data})
    .then(response => response.json()).then(data => {
        if(data.ok)
            getLoginStatus(f);
        else
            f.loginmessage="<b>"+data.message+"</b>"; 
    });
}

function doDeleteImage(f, imageid)
{
    console.log("Attempting to delete "+imageid);
    return fetch("delete-image/" + imageid, {method: "POST"})
        .then(function(res){
            f.imageid="";
            f.can_touch_image=0;
            const url = new URL(window.location.href);
            url.searchParams.delete("i");
            history.pushState({}, "", url);
        });
}

function doChangePublic(f, imageid, el)
{
    let val = el.checked ? "1" : "0";
    el.disabled = true; // disable while transaction is running

    fetch("set-image-public/"+imageid+"/"+val, {method: "POST"}).then(function(res){
        el.disabled = false;

        if(res.ok)
            el.checked = !el.checked; 
    });
}

function processCaptionKey(f, el, e)
{
    if(el.textContent == "...type a caption...") {
        console.log(el);
        el.style.color="#000000";
        el.textContent="";
    }
    if(e.code=="Enter" && e.ctrlKey==true) {
        console.log("Should submit now");
    }
}

function getImage(f, e)
{
    e.preventDefault();

    for (const clipboardItem of e.clipboardData.files) {
        if (clipboardItem.type.startsWith('image/')) {
            const formData = new FormData();
            formData.append('file', clipboardItem, clipboardItem.name);
            
            fetch("upload", {
                method: 'POST',
                body: formData
            })
                .then(response => {
                    if (response.ok) {
                        response.json().then(data => {
                            f.imageid = data.id;
                            f.can_touch_image=1;
                            const url = new URL(window.location.href);
                            url.searchParams.set("i", data.id);
                            history.pushState({}, "", url);
                        });
                    } else {
                        console.error('Error uploading file:', response.statusText);
                    }
                })
            .catch(error => {
                console.error('Network error during file upload', error);
            });
        }
    }
}

