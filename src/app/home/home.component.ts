import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {

  constructor(private router: ActivatedRoute) { }
  isLoggedIn: any;
  ngOnInit(): void {

    this.router.queryParams.subscribe(params =>{
      this.isLoggedIn = params['loggedIn'];
    });

    var html = document.getElementById('home-page');
    if(html != null){
      html.style.display = 'none'
    }
    
  }

}
