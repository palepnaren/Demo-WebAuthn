import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import base64url from 'base64url';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  title = 'angular-webauthn';
  group: FormGroup;

  constructor(private http: HttpClient, private fb: FormBuilder) {
    this.group = this.fb.group({
      name: new FormControl(''),
      username: new FormControl('')
    })

  }
  ngOnInit(): void {

  }

  login() {
    let data = {
      username: this.group.controls['username'].value
    }
    this.http.post('/login', data).subscribe((res: any) => {
      if(res['status'] == 200){
        let idbuff = this._base64ToArrayBuffer(res['data']['allowCredentials'][0]['id']);
        let challenge = this._base64ToArrayBuffer(res['data']['challenge']);
        let publicKey = {
          challenge: challenge,
          id: idbuff,
          userVerification: res['data']['userVerification']
        }
        navigator.credentials.get({ publicKey }).then(res => {
          console.log(res);
        }).catch(error =>{
          console.log(error);
        })
      }
    });
  }

  register() {
    let data = {
      name: this.group.controls['name'].value,
      username: this.group.controls['username'].value
    }
    this.http.post('/register', data).subscribe((res: any) => {
      if(res['status']==400){
        alert("Username already registered");
        return;
      }
      if (res) {
        res = this.convertMakCredResponse(res.data);
        navigator.credentials.create({ publicKey: res }).then(newcreds => {
          console.log(newcreds);
          let assertionRes = this.publicKeyCredentialToJSON(newcreds);
          return this.getPublicKey(assertionRes);
        });
      }
    });
  }

  getPublicKey(response: any) {

    this.http.post('/getPublicKey', response).subscribe((res: any) => {
      localStorage.setItem('publickey', res.data.publickey);
      localStorage.setItem('rawId',res.data.rawId);
    })

  }

  convertMakCredResponse(res: any) {
    let response = {
      challenge: this._base64ToArrayBuffer(res.challenge),
      user: {
        id: this._base64ToArrayBuffer(res.user.id),
        displayName: res.user.displayName,
        name: res.user.name
      },
      pubKeyCredParams: res.pubKeyCredParams,
      rp: {
        id: res.rpId,
        name: "test"
      },
      timeout: res.timeout,
      authenticatorSelection: {
        userVerification: res.userVerification,
        authenticatorAttachment: res.authenticatorAttachment
      }
    }
    return response;
  }

  _base64ToArrayBuffer(base64: string) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  }

  publicKeyCredentialToJSON(pubKeyCred: any) {
    let _pubKeyCred = {
      authenticatorAttachment: '',
      id: '',
      rawId: '',
      type: '',
      response: {
        attestationObject: '',
        clientDataJSON: ''
      }
    }

    if (pubKeyCred) {
      if (pubKeyCred.rawId instanceof ArrayBuffer) {

        _pubKeyCred.rawId = this.toBase64(pubKeyCred.rawId);

      }

      if (pubKeyCred.response) {
        if (pubKeyCred.response.attestationObject instanceof ArrayBuffer) {
          _pubKeyCred.response.attestationObject = this.toBase64(pubKeyCred.response.attestationObject);
        }
        if (pubKeyCred.response.clientDataJSON instanceof ArrayBuffer) {
          _pubKeyCred.response.clientDataJSON = this.toBase64(pubKeyCred.response.clientDataJSON);
        }
      }
      _pubKeyCred.type = pubKeyCred.type;
      _pubKeyCred.id = pubKeyCred.id;
      _pubKeyCred.authenticatorAttachment = pubKeyCred.authenticatorAttachment;

    }
    return _pubKeyCred;
  }

  toBase64(value: ArrayBuffer) {
    const array = new Uint8Array(value);
    const STRING_CHAR = array.reduce((data, byte) => {
      return data + String.fromCharCode(byte);

    }, '');
    let base64String = window.btoa(STRING_CHAR);
    return base64String;
  }


}
