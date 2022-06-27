'use strict';


/* Handle for register form submission */
$('#register').submit(function (event) {
    event.preventDefault();

    let username = this.username.value;
    let name = this.name.value;

    if (!username || !name) {
        alert('Name or username is missing!')
        return
    }
    getMakeCredentialsChallenge({ username, name })
        .then((response) => {
            let publicKey = preformatMakeCredReq(response);
            console.log(publicKey);
            return navigator.credentials.create({ publicKey: publicKey });
        }).then(newCred => {
            let makeCredResponse = publicKeyCredentialToJSON(newCred);
            return sendWebAuthnResponse(makeCredResponse);
        })

})

/* Handle for login form submission */
$('#login').submit(function(event) {
    event.preventDefault();

    let username = this.username.value;

    if(!username) {
        alert('Username is missing!')
        return
    }

    getGetAssertionChallenge({username})
        .then((response) => {
            let publicKey = preformatGetAssertReq(response);
            return navigator.credentials.get({ publicKey })
        })
        .then((response) => {
            let getAssertionResponse = publicKeyCredentialToJSON(response);
            return sendWebAuthnResponse(getAssertionResponse)
        })
        .then((response) => {
            if(response.status === 'ok') {
                loadMainContainer()   
            } else {
                alert(`Server responed with error. The message is: ${response.message}`);
            }
        })
        .catch((error) => alert(error))
})


let getMakeCredentialsChallenge = (formBody) => {
    console.log("Register called");
    // return fetch('/webauthn/register', {
    //     method: 'POST',
    //     credentials: 'include',
    //     headers: {
    //         'Content-Type': 'application/json'
    //     },
    //     body: JSON.stringify(formBody)
    // })
    //     .then((response) => {
    //         console.log(response.body);
    //         let makeCredResponse = publicKeyCredentialToJSON(response);
    //         return sendWebAuthnResponse(makeCredResponse)
    //     })
    //     .then((response) => {
    //         if(response.status === 'ok') {
    //             console.log(response);
    //             loadMainContainer()   
    //         } else {
    //             alert(`Server responed with error. The message is: ${response.message}`);
    //         }
    //         // return response
    //     })
    //     .catch( error => alert(error));

    return $.ajax({
        type: 'POST',
        url: '/webauthn/register',
        xhrFields: {
            withCredentials: true
        },
        headers: {
            'Content-Type': 'application/json'
        },
        data: JSON.stringify(formBody),
        dataType: 'json' ,
        success: function(response){
            // let makeCredResponse = publicKeyCredentialToJSON(response);
            // console.log(makeCredResponse);
            // return sendWebAuthnResponse(makeCredResponse);
            return response;
        },
        error: function(response){
            alert(response);
        }
    })
}


let sendWebAuthnResponse = (body) => {
    // return fetch('/webauthn/response', {
    //     method: 'POST',
    //     credentials: 'include',
    //     headers: {
    //         'Content-Type': 'application/json'
    //     },
    //     body: JSON.stringify(body)
    // })
    //     .then((response) => response.json())
    //     .then((response) => {
    //         if (response.status !== 'ok')
    //             throw new Error(`Server responed with error. The message is: ${response.message}`);

    //         return response
    //     })

    return $.ajax({
        type: 'POST',
        url: '/webauthn/response',
        xhrFields: {
            withCredentials: true
        },
        headers: {
            'Content-Type': 'application/json'
        },
        data: JSON.stringify(body),
        dataType: 'json' ,
        success: function(response){
            console.log(response);
            if(response.status !== 'ok'){
                throw new Error(`Server responed with error. The message is: ${response.message}`);
            }

            return response;
        },
        error: function(response){
            alert(response);
        }
    })
}

let getGetAssertionChallenge = (formBody) => {
    return fetch('/webauthn/login', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The message is: ${response.message}`);

        return response
    })
}