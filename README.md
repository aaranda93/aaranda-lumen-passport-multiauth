# Lumen Passport Multi-Auth



Add passport and multi-authentication support to [Lumen](https://lumen.laravel.com/)

## Compatibility


| Lumen Framework  | 
|--------------------|
| >= 8.0             | 


## Installing 

Install using composer:

```sh
$ composer require aaranda/lumen-passport-multiauth:^0.1
```

## Configuration

First of all, you will need to publish your Lumen configuration folder
```sh
cp -a vendor/laravel/lumen-framework/config config
```
so you can add the new providers and guards you want to use.


You need to uncomment and add some lines in your bootstrap/app.php file

```php

//uncomment
    $app->withFacades();
//uncomment
    $app->withEloquent();


//add in the config file section
    $app->configure('auth');


//Uncomment your route middleware and add the next lines
    $app->routeMiddleware([
        'auth'     => App\Http\Middleware\Authenticate::class,
        'client' => App\Http\Middleware\CheckClientCredentials::class,
        'throttle' => Aaranda\LumenPassportMultiauth\Http\Middleware\ThrottleRequests::class,
        'oauth.providers' => Aaranda\LumenPassportMultiauth\Http\Middleware\AddCustomProvider::class,
        'multiauth' => Aaranda\LumenPassportMultiauth\Http\Middleware\MultiAuthenticate::class,

        //if you are going to use scopes, you can add the next route middlewares
        'scopes' => Laravel\Passport\Http\Middleware\CheckScopes::class,
        'scope' => Laravel\Passport\Http\Middleware\CheckForAnyScope::class,

    ]);

//and register the next service providers in this same order
    $app->register(App\Providers\AuthServiceProvider::class);
    $app->register(Aaranda\LumenPassportMultiauth\Providers\MultiauthServiceProvider::class);
    $app->register(Laravel\Passport\PassportServiceProvider::class);


```

Encapsulate and register the passport routes for access token with the registered middleware in `AuthServiceProvider` in 
app/Providers/AuthServiceProvider.php. 
This middleware will add the capability to `Passport` route `oauth/token` use the value of `provider` param on request:

```php

namespace App\Providers;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Aaranda\LumenPassportMultiauth\Passport;
use Illuminate\Support\Facades\Route;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Boot the authentication services for the application.
     *
     * @return void
     */
    public function boot()
    {

        Route::group(['middleware' => 'oauth.providers'], function () {
    
            Passport::routes(function ($router) {
                return $router->forAccessTokens();
            });
        });

        // change the default token expiration
        Passport::tokensExpireIn(Carbon::now()->addDays(15));

        // change the default refresh token expiration
        Passport::refreshTokensExpireIn(Carbon::now()->addDays(30));

    }
}

```




create in your App\Http\Middleware folder a CheckClientCredentials.php file

```php

namespace App\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Laravel\Passport\Exceptions\MissingScopeException;

class CheckClientCredentials extends CheckCredentials
{
    /**
     * Validate token credentials.
     *
     * @param  \Laravel\Passport\Token  $token
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    protected function validateCredentials($token)
    {
        if (! $token) {
            return response('Unauthorized.', 401);
        }
    }

    /**
     * Validate token credentials.
     *
     * @param  \Laravel\Passport\Token  $token
     * @param  array  $scopes
     * @return void
     *
     * @throws \Laravel\Passport\Exceptions\MissingScopeException
     */
    protected function validateScopes($token, $scopes)
    {
        if (in_array('*', $token->scopes)) {
            return;
        }

        foreach ($scopes as $scope) {
            if ($token->cant($scope)) {
                throw new MissingScopeException($scope);
            }
        }
    }
}

```

and a CheckCredentials.php file

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

abstract class CheckCredentials
{
    /**
     * The Resource Server instance.
     *
     * @var \League\OAuth2\Server\ResourceServer
     */
    protected $server;

    /**
     * Token Repository.
     *
     * @var \Laravel\Passport\TokenRepository
     */
    protected $repository;

    /**
     * Create a new middleware instance.
     *
     * @param  \League\OAuth2\Server\ResourceServer  $server
     * @param  \Laravel\Passport\TokenRepository  $repository
     * @return void
     */
    public function __construct(ResourceServer $server, TokenRepository $repository)
    {
        $this->server = $server;
        $this->repository = $repository;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  mixed  ...$scopes
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle($request, Closure $next, ...$scopes)
    {
        $psr = (new PsrHttpFactory(
            new Psr17Factory,
            new Psr17Factory,
            new Psr17Factory,
            new Psr17Factory
        ))->createRequest($request);

        try {
            $psr = $this->server->validateAuthenticatedRequest($psr);
        } catch (OAuthServerException $e) {
            return response('Unauthorized.', 401);
        }

        $this->validate($psr, $scopes);

        return $next($request);
    }

    /**
     * Validate the scopes and token on the incoming request.
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $psr
     * @param  array  $scopes
     * @return void
     *
     * @throws \Laravel\Passport\Exceptions\MissingScopeException|\Illuminate\Auth\AuthenticationException
     */
    protected function validate($psr, $scopes)
    {
        $token = $this->repository->find($psr->getAttribute('oauth_access_token_id'));

        $this->validateCredentials($token);

        $this->validateScopes($token, $scopes);
    }

    /**
     * Validate token credentials.
     *
     * @param  \Laravel\Passport\Token  $token
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    abstract protected function validateCredentials($token);

    /**
     * Validate token scopes.
     *
     * @param  \Laravel\Passport\Token  $token
     * @param  array  $scopes
     * @return void
     *
     * @throws \Laravel\Passport\Exceptions\MissingScopeException
     */
    abstract protected function validateScopes($token, $scopes);
}

```





Now we you need to add the necessary classes to the models you are going to use for your providers
Lets say you are going to use a User model and a Admin model, so you are going to need to declare them like:

```php
namespace App;


use Aaranda\LumenPassportMultiauth\HasMultiAuthApiTokens;
use Illuminate\Auth\Authenticatable;
use Laravel\Lumen\Auth\Authorizable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;

class User extends Model implements AuthenticatableContract, AuthorizableContract
{
    use HasMultiAuthApiTokens, Authenticatable, Authorizable;

    // rest of the model
}

```

and

```php

namespace App;


use Aaranda\LumenPassportMultiauth\HasMultiAuthApiTokens;
use Illuminate\Auth\Authenticatable;
use Laravel\Lumen\Auth\Authorizable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;

class Admin extends Model implements AuthenticatableContract, AuthorizableContract
{
    use HasMultiAuthApiTokens, Authenticatable, Authorizable;

    // rest of the model
}

```






now that you have all the neccessary steps,
in you recently published config folder

you can add your new custom providers and guards in your `config/auth.php` file


```php

    'providers' => [

//user provider
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],

// admin provider  
        'admins' => [
            'driver' => 'eloquent',
            'model' => App\Models\Admin::class,
        ],
    ],



    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
//user guard
        'users' => [
            'driver' => 'passport',
            'provider' => 'users', 
        ],

//admin guard
        'admin' => [
            'driver' => 'passport',
            'provider' => 'admins',
        ],
    ],

    
```


Finally you need to migrate your passport tables 

```sh

php artisan migrate

```

and other necessary stuff for Passport like ancription keys

```sh

php artisan passport:install

```

## Usage

Add the `provider` parameter in your request at `/oauth/token`:

```http
POST /oauth/token HTTP/1.1
Host: localhost
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache

{
    "username":"user@domain.com",
    "password":"password",
    "grant_type" : "password",
    "client_id": "client-id",
    "client_secret" : "client-secret",
    "provider" : "admins"
}
```

You can pass your guards on `multiauth` middleware as you wish. Example:

```php
Route::group(['middleware' => ['api', 'multiauth:admin']], function () {
    Route::get('/admin', function ($request) {
        // Get the logged admin instance
        return $request->user(); // You can use too `$request->user('admin')` passing the guard.
    });
});

```

The  `api` guard use is equals the example with `admin`.

You can pass many guards to `multiauth` middleware.

```php
Route::group(['middleware' => ['api', 'multiauth:admin,api']], function () {
    Route::get('/admin', function ($request) {
        // The instance of user authenticated (Admin or User in this case) will be returned
        return $request->user();
    });
});
```


### Refreshing tokens

Add the `provider` parameter in your request at `/oauth/token`:

```http
POST /oauth/token HTTP/1.1
Host: localhost
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache

{
    "grant_type" : "refresh_token",
    "client_id": "client-id",
    "client_secret" : "client-secret",
    "refresh_token" : "refresh-token",
    "provider" : "admins"
}
```


### Contributors

Based on [renanwilian's](https://github.com/nomadnt) [lumen-passport](https://github.com/nomadnt/lumen-passport).
