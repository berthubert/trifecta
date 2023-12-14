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
        f.can_touch_post=0;
        let p = a.searchParams.get("p");
        if(p != null) {
            f.postId = p;
            console.log("Set postid");
            fetch('getPost/'+f.postId).then(response => response.json()).then(data => {
                f.images = data.images;
                f.postTitle = data.title;
            });
            fetch('can_touch_post/'+f.postId).then(response => {
                if (response.ok) {
                    response.json().then(data => {
                         f.can_touch_post = data.can_touch_post;
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
        f.myimages = data;
    });
}

function doSetPostTitle(f, el)
{
    const formData = new FormData();
    formData.append('title', el.innerText);
    
    fetch("set-post-title/"+f.postId, {method: "POST", body: formData});
}

function doLogin(el, f)
{
    const data = new URLSearchParams(new FormData(el));
    fetch("login", {method: "POST", body: data})
    .then(response => response.json()).then(data => {
        if(data.ok) {
            f.message2user="";
            getLoginStatus(f);
        }
        else
            f.loginmessage=data.message; 
    });
}

function doDeleteImage(f, imageid)
{
    console.log("Attempting to delete "+imageid);
    return fetch("delete-image/" + imageid, {method: "POST"})
        .then(function(res){
            if(res.ok) {
                f.images = f.images.filter(function(item) {
                    return item.id !== imageid;
                })
            }
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

function processCaptionKey(f, el, e, imageid)
{
    if(el.textContent == "...type a caption...") {
        el.style.color="#000000";
        el.textContent="";
    }
    if(e.code=="Enter" && e.ctrlKey==true) {
        const formData = new FormData();
        formData.append('caption', el.innerHTML);
        
        fetch("set-image-caption/"+ imageid, {method: "POST", body: formData});
    }
}

// this uploads an image, possibly to an existing post. If there is no post yet, it receives
// the post that was created for us
function getImageFromPaste(f, e)
{
    e.preventDefault();
    if(!f.loggedon) {
        f.message2user="Please login to paste an image.";
        return;
    }
    for (const clipboardItem of e.clipboardData.files) {
        if (clipboardItem.type.startsWith('image/')) {
            const formData = new FormData();
            if(f.postId != '')
                formData.append('postId', f.postId);
            formData.append('file', clipboardItem, clipboardItem.name);

            fetch("upload", {
                method: 'POST',
                body: formData
            })
                .then(response => {
                    if (response.ok) {
                        response.json().then(data => {
                            f.images.push({"id": data.id});
                            f.postId = data.postId;
                            f.can_touch_post=1;
                            const url = new URL(window.location.href);
                            url.searchParams.set("p", data.postId); 
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

