<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Auth;

class UserController extends Controller
{

    public function store(Request $request)
{
    // Validar los datos de entrada
    $validatedData = $request->validate([
        'name' => 'required|max:255',
        'email' => 'required|email|unique:users',
        'password' => 'required|min:6',
        'rol' => 'required|min:6',
    ]);

    // Crear el usuario
    $user = User::create([
        'name' => $validatedData['name'],
        'email' => $validatedData['email'],
        'password' => bcrypt($validatedData['password']),
        'rol' => $validatedData['rol'],
    ]);

    // Opcionalmente, puedes generar un token de acceso para el usuario
    $token = $user->createToken('example')->accessToken;

    // Enviar respuesta
    return response()->json(['user' => $user, 'token' => $token], 201);
}

    /**
     * Display a listing of the resource.
     */
    public function loginUser(Request $request): Response
{
    $input = $request->all();

    if (Auth::attempt($input)) {
        $user = Auth::user();
        $token = $user->createToken('example')->accessToken;

        // Asegúrate de que el modelo User tenga un método para obtener el rol
        // Por ejemplo, podría ser un método llamado 'role' que devuelva la relación
        $role = $user->rol; // O la lógica adecuada para obtener el rol

        return Response([
            'status' => 200, 
            'token' => $token,
            'user' => $user->toArray(), // O la información específica que quieras incluir
            'role' => $role // Aquí agregas el rol
        ], 200);
    } else {
        return Response(['error' => 'Unauthorized'], 401);
    }
}


    /**
     * Store a newly created resource in storage.
     */
    public function getUserDetail(): Response
    {
        if(Auth::guard('api')->check()){
            $user = Auth::guard('api')->user();
            return Response(['data' => $user],200);
        }
        return Response(['data' => 'Unauthorized'],401);
    }

    /**
     * Display the specified resource.
     */
    public function userLogout(): Response
    {
        if(Auth::guard('api')->check()){
            $accessToken = Auth::guard('api')->user()->token();

                \DB::table('oauth_refresh_tokens')
                    ->where('access_token_id', $accessToken->id)
                    ->update(['revoked' => true]);
            $accessToken->revoke();

            return Response(['data' => 'Unauthorized','message' => 'User logout successfully.'],200);
        }
        return Response(['data' => 'Unauthorized'],401);
    }

    public function resetPasswordByEmail(Request $request): Response
{
    // Validar los datos de entrada
    $validatedData = $request->validate([
        'email' => 'required|email|exists:users,email',
        'new_password' => 'required|min:6|confirmed',
    ]);

    // Buscar al usuario por email
    $user = User::where('email', $validatedData['email'])->first();

    if (!$user) {
        return Response(['error' => 'Usuario no encontrado'], 404);
    }

    // Actualizar la contraseña
    $user->password = bcrypt($validatedData['new_password']);
    $user->save();

    // Aquí puedes enviar una notificación al usuario informando del cambio

    return Response(['message' => 'Contraseña actualizada con éxito'], 200);
}

public function getAllUsers(): Response
{
    $users = User::all();

    return Response(['data' => $users], 200);
}

}
