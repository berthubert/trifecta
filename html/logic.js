"use strict";


async function doPageLoad(f) {

    await getLoginStatus(f);
    getMyImageList(f);
    getPost(f);
    if (f.user.isadmin === true) {
        console.log("is admin user");
    }
    
}



async function getLoginStatus(f) {
    f.user = {
        loggedon: false,
        name: '',
        isAdmin: false
    }
    const response = await fetch('status');
    if (response.ok === true) {
        const data = await response.json();
        if (data.login) {
            f.user.name = data.user;
            f.user.loggedon = true;
            f.user.isadmin = data.admin;
        }
    }
}

async function getPost(f) {
    f.post = {
        id: null,
        images: [],
        can_touch_post: false,
    };
    let url = new URL(window.location.href)
    let p = url.searchParams.get("p");
    if (p != null) {
        f.post.id = p;
        fetch(`getPost/${f.post.id}`).then(response => response.json()).then(data => {
            f.post.images = data.images;
            f.post.title = data.title;
            f.post.public = data.public;
            f.post.publicuntil = data.publicUntil;
            f.post.can_touch_post = data.can_touch_post;
        });
    }
}

function doLogout(f) {
    fetch("logout", { method: "POST" })
        .then(function (res) {
            getLoginStatus(f);
            f.myimages = [];
        });
}

function getImageList(f) {
    fetch('all-images').then(response => response.json()).then(data => {
        f.images = data;
    });
}
function getUserList(f) {
    fetch('all-users').then(response => response.json()).then(data => {
        f.users = data;
    });
}

function getSessionList(f) {
    fetch('all-sessions').then(response => response.json()).then(data => {
        f.sessions = data;
    });
}


function getMyImageList(f) {
    fetch('my-images').then(response => response.json()).then(data => {
        f.myimages = data;
    });
}

function doSetPostTitle(f, el) {
    const formData = new FormData();
    formData.append('title', el.value);

    fetch("set-post-title/" + f.postId, { method: "POST", body: formData });
}

function doLogin(el, f) {
    const data = new FormData(el);
    fetch("login", { method: "POST", body: data })
        .then(response => response.json()).then(data => {
            if (data.ok) {
                f.message2user = "";
                getLoginStatus(f);
                getMyImageList(f);
            }
            else
                f.message2user = data.message;
        });
}

function doDeleteImage(f, imageid) {
    if (window.confirm("Do you really want to delete this image?")) {
        fetch("delete-image/" + imageid, { method: "POST" })
            .then(function (res) {
                if (res.ok) {
                    f.images = f.images.filter(function (item) {
                        return item.id !== imageid;
                    })
                }
            });
    }
}

function doDeletePost(f, postid) {
    if (window.confirm("Do you really want to delete this post?")) {
        fetch("delete-post/" + postid, { method: "POST" })
            .then(function (res) {
                if (res.ok) {
                    window.location.href = "./";
                }
            });
    }
}

function doKillSession(f, sessionid) {
    fetch("kill-session/" + sessionid, { method: "POST" }).then(function (res) {
        if (res.ok) {
            getSessionList(f);
        }
    });
}

function doDelUser(f, user) {
    if (window.confirm("Do you really want to delete this user?")) {
        fetch("del-user/" + user, { method: "POST" }).then(function (res) {
            if (res.ok) {
                getUserList(f);
            }
        });
    }
}


function doChangePublic(f, postid, el) {
    let val = el.checked ? "1" : "0";
    el.disabled = true; // disable while transaction is running

    fetch("set-post-public/" + postid + "/" + val, { method: "POST" }).then(function (res) {
        el.disabled = false;

        if (res.ok) {
            el.checked = !el.checked;
            f.post.public = el.checked ? 1 : 0; // we need to propagate this manually
            // because we prevented normal event processing
            getMyImageList(f);
        }
    });
}

//todo: remove el
function doChangePublicUntil(f, postid, el, seconds) {
    let limit = (Date.now() / 1000 + seconds).toFixed();
    if (seconds == 0)
        limit = 0;
    fetch(`set-post-public/${postid}/${f.post.public}/${limit}`, { method: "POST" }).then(function (res) {
        if (res.ok) {
            f.post.publicuntil = limit; // we need to propagate this manually
            getMyImageList(f);
        }
    });
}

//todo: remove f?
function doChangeUserDisabled(f, user, el) {
    let val = el.checked ? "1" : "0";
    el.disabled = true; // disable while transaction is running

    fetch(`change-user-disabled/${user}/${val}`, { method: "POST" }).then(function (res) {
        el.disabled = false;

        if (res.ok)
            el.checked = !el.checked;
    });
}


//todo remove f, e?
function processCaptionKey(f, el, e, imageid) {
    const formData = new FormData();
    formData.append('caption', el.value);

    fetch(`set-image-caption/${imageid}`, { method: "POST", body: formData });
}

async function uploadFile(clipboardItem, f) {
    if (clipboardItem.type.startsWith('image/')) {
        const formData = new FormData();
        if (f.postId != '') {
            console.log("Passing known postId: " + f.postId);
            formData.append('postId', f.postId);
        }
        formData.append('file', clipboardItem, clipboardItem.name);

        await fetch("upload", {
            method: 'POST',
            body: formData
        })
            .then(response => {
                if (response.ok) {
                    // this "return" is what makes the chaining work
                    return response.json().then(data => {
                        f.post.images.push({ "id": data.id });
                        f.post.id = data.postId;
                        f.post.public = data.public;
                        f.post.publicuntil = data.publicUntil;

                        console.log("Set postId to " + f.postId);
                        f.post.can_touch_post = 1;
                        const url = new URL(window.location.href);
                        url.searchParams.set("p", data.postId);
                        history.pushState({}, "", url);
                        getMyImageList(f);
                    });
                } else {
                    console.error('Error uploading file:', response.statusText);
                }
            })
            .catch(error => {
                console.error('Network error during file upload', error);
            });
    }
    else
        console.log("Don't know how to deal with paste of " + clipboardItem.type);

}

// this uploads an image, possibly to an existing post. If there is no post yet, it receives
// the post that was created for us
async function getImageFromPaste(f, e) {
    e.preventDefault();
    if (!f.loggedon) {
        f.message2user = "Please login to paste an image.";
        return;
    }

    let files = e.clipboardData.files;
    if (files.length > 0) {
        await uploadFile(files[0], f);
        for (let n = 1; n < files.length; ++n) {
            console.log("Start upload " + n);
            uploadFile(files[n], f);
        }
    }
}

async function processDrop(f, e) {
    if (!f.user.loggedon) {
        f.message2user = "Please login to paste an image.";
        return;
    }
    let files = e.dataTransfer.files;

    if (files.length > 0) {
        await uploadFile(files[0], f);
        for (let n = 1; n < files.length; ++n) {
            uploadFile(files[n], f);
        }
    }
}

function doCreateUser(el, f) {
    let user = el[0].value;
    let pass1 = el[1].value;
    let pass2 = el[2].value;
    f.message2user = "";
    if (pass1 != pass2) {
        f.message2user = "<span class='error'>Passwords do not match</span>";
        return;
    }

    fetch("create-user", { method: "POST", body: new FormData(el) }).then(response => {
        if (response.ok) {
            response.json().then(data => {
                if (data.ok) {
                    f.message2user = "User created";
                    getUserList(f);
                }
                else
                    f.message2user = data.message;
            });
        }
        else
            f.message2user = "Error sending creation request";
    });
}
