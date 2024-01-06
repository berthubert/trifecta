"use strict";


async function doPageLoad(f) {
    if (window.location.hash != "") {
        f.showSection = window.location.hash.substring(1);
    }

    await getLoginStatus(f);
    getMyImageList(f);
    getPost(f);
    if (f.user.isadmin === true) {
        console.log("is admin user");
    }
}

function ShowMessage(f, msg, error = undefined) {
    f.message2user = msg;
    const messagespan = document.querySelector("#userfeedback > span");
    messagespan.classList.remove("error");

    if (error != undefined) {
        console.log(error);
        messagespan.classList.add("error");
    }
}
function ClearMessage(f) {
    f.message2user = "";
}


async function getLoginStatus(f) {
    f.user = {
        name: '',
        loggedon: false,
        isadmin: false,
        email: '',
        hasPw: false
    }
    const response = await fetch('status');
    if (response.ok === true) {
        const data = await response.json();
        if (data.login) {
            f.user.name = data.user;
            f.user.loggedon = true;
            f.user.isadmin = data.admin;
            f.user.email = data.email;
            f.user.hasPw = data.hasPw;
        }
        f.version = data.version;
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
        if(Array.isArray(data)) // otherwise we attempt to show errors as images
            f.images = data;
    });
}
function getUserList(f) {
    console.log("getuserlist called");
    fetch('all-users').then(response => response.json()).then(data => {
        f.users = data;
    });
}

function getSessionList(f) {
    fetch('all-sessions').then(response => response.json()).then(data => {
        f.sessions = data;
    });
}

function getMySessionList(f) {
    fetch('my-sessions').then(response => response.json()).then(data => {
        f.sessions = data;
    });
}


function getMyImageList(f) {
    fetch('my-images').then(response => response.json()).then(data => {
        if(Array.isArray(data)) {
            // order by postid so that images for the same post are together
            f.myimages = data.sort((a, b) => {
                return a.postId < b.postId;
            })
        }
    });
}

function doSetPostTitle(f, el) {
    const formData = new FormData();
    formData.append('title', el.value);

    fetch(`set-post-title/${f.post.id}`, { method: "POST", body: formData });
}

function doLogin(el, f) {
    const data = new FormData(el);
    fetch("login", { method: "POST", body: data })
        .then(response => response.json()).then(data => {
            if (data.ok) {
                f.user.suggestEmail = false;
                ClearMessage(f);
                getLoginStatus(f);
                getMyImageList(f);
            }
            else {
                ShowMessage(f, data.message);
            }
        });
}

function doAskForSigninEmail(user, f) {
    const formData = new FormData();
    formData.append('user', user);

    fetch("get-signin-email", { method: "POST", body: formData })
        .then(response => response.json()).then(data => {
            if (data.ok) {
                ShowMessage(f, data.message);
            }
            else {
                ShowMessage(f, data.message);
            }
        });
}


function doDeleteImage(f, imageid) {
    if (window.confirm("Do you really want to delete this image?")) {
        fetch(`delete-image/${imageid}`, { method: "POST" })
            .then(function (res) {
                if (res.ok) {
                    f.post.images = f.post.images.filter(function (item) {
                        return item.id !== imageid;
                    })
                }
                getMyImageList(f);
            });
    }
}

function doDeletePost(f) {
    if (window.confirm("Do you really want to delete this post?")) {
        fetch(`delete-post/${f.post.id}`, { method: "POST" })
            .then(function (res) {
                if (res.ok) {
                    window.location.href = "./";
                }
            });
    }
}

function doKillSession(f, sessionid) {
    fetch(`kill-session/${sessionid}`, { method: "POST" }).then(function (res) {
        if (res.ok) {
            getSessionList(f);
        }
    });
}

function doKillMySession(f, sessionid) {
    fetch(`kill-my-session/${sessionid}`, { method: "POST" }).then(function (res) {
        if (res.ok) {
            getMySessionList(f);
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
    let newval = el.checked ? 1 : 0;
    el.disabled = true; // disable while transaction is running

    // the return makes us thennable
    return fetch(`set-post-public/${postid}/${newval}`, { method: "POST" }).then(function (res) {
        el.disabled = false;
        if (res.ok) {
            f.post["public"] = newval;
        } else {
            ShowMessage(f, "Failed to change post public status", res);
        }
    }); 
}

function doChangePublicUntil(f, postid, seconds) {
    let limit = (Date.now() / 1000 + seconds).toFixed();
    if (seconds == 0)
        limit = 0;
    fetch(`set-post-public/${postid}/1/${limit}`, { method: "POST" }).then(function (res) {
        if (res.ok) {
            f.post.publicuntil = limit; // we need to propagate this manually
        }
        else {
            ShowMessage(f, "Failed to change post public until", res);
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


function processCaptionKey(f, el, e, imageid) {
    const formData = new FormData();
    formData.append('caption', el.value);

    fetch(`set-image-caption/${imageid}`, { method: "POST", body: formData });
}

async function uploadFile(clipboardItem, f) {
    if (clipboardItem.type.startsWith('image/')) {
        const formData = new FormData();
        if (f.post.id != null) {
            console.log("Passing known postId: " + f.post.id);
            formData.append('postId', f.post.id);
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

                        console.log("Set postId to " + f.post.id);
                        f.post.can_touch_post = 1;
                        const url = new URL(window.location.href);
                        url.searchParams.set("p", f.post.id);
                        history.pushState({}, "", url);
                        getMyImageList(f);
                    });
                } else {
                    ShowMessage(f, "Error uploading file.", response);
                }
            })
            .catch(error => {
                ShowMessage(f, "Network error duing file upload.", error);
            });
    }
    else {
        ShowMessage(f, `We don't support the paste type ${clipboardItem.type}`);
    }
}

// this uploads an image, possibly to an existing post. If there is no post yet, it receives
// the post that was created for us
async function getImageFromPaste(f, e) {
    e.preventDefault();
    if (!f.user.loggedon) {
        ShowMessage(f, "Please login to paste an image.");
        return;
    }

    let files = e.clipboardData.files;
    if (files.length > 0) {
        await uploadFile(files[0], f);
        for (let n = 1; n < files.length; ++n) {
            uploadFile(files[n], f);
        }
    }
}

async function processDrop(f, e) {
    if (!f.user.loggedon) {
        ShowMessage(f, "Please login to paste an image.");
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
    let pass1 = el[2].value;
    let pass2 = el[3].value;
    ClearMessage(f);
    if (pass1 != pass2) {
        ShowMessage(f, "Passwords do not match", true);
        return;
    }

    return fetch("create-user", { method: "POST", body: new FormData(el) }).then(function(response)  {
        if (response.ok) {
            return response.json().then(data => {
                if (data.ok) {
                    console.log("Response in");
                    ShowMessage(f, "User created");
                }
                else {
                    ShowMessage(f, `Could not create user: ${data.message}`);
                }
            });
        }
        else {
            ShowMessage(f, "Failed to create user.", response);
        }
    });
}


function doChangeMyPassword(el, f) {
    let pass1 = el["password1"].value;
    let pass2 = el["password2"].value;
    ClearMessage(f);
    if (pass1 != pass2) {
        ShowMessage(f, "Passwords do not match", true);
        return;
    }

    return fetch("change-my-password", { method: "POST", body: new FormData(el) }).then(function(response)  {
        if (response.ok) {
            return response.json().then(data => {
                if (data.ok) {
                    ShowMessage(f, "Changed password");
                    f.user.hasPw = true;
                }
                else {
                    ShowMessage(f, `Could not change password: ${data.message}`, response);
                }
            });
        }
        else {
            ShowMessage(f, "Failed to change password", response);
        }
    });
}

function doChangeMyEmail(el, f) {
    ClearMessage(f);

    return fetch("change-my-email", { method: "POST", body: new FormData(el) }).then(function(response)  {
        if (response.ok) {
            return response.json().then(data => {
                if (data.ok) {
                    ShowMessage(f, "Changed email");
                }
                else {
                    ShowMessage(f, `Could not change email: ${data.message}`, response);
                }
            });
        }
        else {
            ShowMessage(f, "Failed to change email", response);
        }
    });
}
