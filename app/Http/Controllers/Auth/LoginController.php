<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class LoginController extends Controller
{
    use AuthenticatesUsers, ThrottlesLogins;

    protected $redirectTo = RouteServiceProvider::HOME;

    protected $maxAttempts = 3;
    protected $decayMinutes = 30;

    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function login(Request $request)
    {
        $this->ensureIsNotRateLimited($request);
        $request->validate([
            $this->username() => 'required|string',
            'password' => 'required|string',
            'captcha' => 'required|captcha',
        ], [
            'captcha.required' => 'Please enter the captcha.',
            'captcha.captcha' => 'The captcha is incorrect. Please try again.',
        ]);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptLogin($request)) {
            return $this->sendLoginResponse($request);
        }

        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }

    protected function hasTooManyLoginAttempts(Request $request)
    {
        return $this->limiter()->tooManyAttempts(
            $this->throttleKey($request),
            $this->maxAttempts,
            $this->decayMinutes
        );
    }

    protected function incrementLoginAttempts(Request $request)
    {
        $this->limiter()->hit(
            $this->throttleKey($request)
        );
    }

    protected function ensureIsNotRateLimited(Request $request)
    {
        if ($this->limiter()->tooManyAttempts($this->throttleKey($request), $this->maxAttempts)) {
            $seconds = $this->limiter()->availableIn($this->throttleKey($request));
            $this->fireLockoutEvent($request);
            throw ValidationException::withMessages([
                $this->username() => [trans('auth.throttle', ['seconds' => $seconds])],
            ])->status(Response::HTTP_TOO_MANY_REQUESTS);
        }
    }

    protected function sendFailedLoginResponse(Request $request)
    {
        throw ValidationException::withMessages([
            $this->username() => [trans('auth.failed')],
        ])->status(Response::HTTP_UNAUTHORIZED);
    }
}
