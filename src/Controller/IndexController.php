<?php

namespace App\Controller;

use App\Entity\RecoverAccount;
use App\Entity\User;
use App\Repository\RecoverAccountRepository;
use App\Repository\UserRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

class IndexController extends AbstractController
{
    #[Route('/', name: 'app_index')]
    public function index(): Response
    {
        $redireccion = new RedirectResponse('/');

        $redireccion->setTargetUrl('https://oauth.genotipia.com/public/index.php/authorize?response_type=code&client_id=CerebroDev&redirect_uri=' . $_ENV['URL_REDIRECT'] . '&scope=profile%20email');
        return $redireccion;
    }

    #[Route('/api/test', name: 'app_api_test')]
    public function apiTest(): Response
    {
        /** @var User $user */
        $user = $this->getUser();
        return $this->json([
            'message' => 'Autenticado con éxito',
            'email' => $user->getEmail(),
            'openid' => $user->getUuid()->toRfc4122(),
            'name' => $user->getName(),
            'apellido' => $user->getSurname()
        ]);
    }

    #[Route('/change-mail-api', name: 'app_change_mail_api', methods: ['POST'])]
    public function apiChangeMailApi(Request $request, ManagerRegistry $doctrine, UserRepository $userRepository): Response
    {
        //mirar si la llamada tiene la cabecera authorization
        $authorization = $request->headers->get('authorization');
        if (!$authorization) {
            return $this->json([
                'message' => 'No tienes permisos para hacer esto',
                'success' => false
            ]);
        }
        if ("!CUKJ56*>Olq*0@dkD3Prq2g" != $authorization) {
            return $this->json([
                'message' => 'No tienes permisos para hacer esto 2',
                'success' => false
            ]);
        }

        $request = $this->transformJsonBody($request);

        $email = $request->get('oldEmail');
        $new_email = $request->get('newEmail');
        $user = $userRepository->findOneBy(['email' => $email]);
        $this->json([
            'message' => 'Usuario no encontrado',
            'user' => $user->getEmail(),
            'success' => false
        ]);
        if (!$user) {
            return $this->json([
                'message' => 'Usuario no encontrado',
                'success' => false
            ]);
        }
        $user->setEmail($new_email);
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->flush();
        return $this->json([
            'message' => 'Correo electrónico cambiado con éxito',
            'success' => true
        ]);
    }

    #[Route('/api/change-mail', name: 'app_change_mail', methods: ['POST'])]
    public function apiChangeMail(Request $request, ManagerRegistry $doctrine, UserRepository $userRepository): Response
    {
        $request = $this->transformJsonBody($request);

        $userAdmin = $this->getUser();
        $permisos = $userAdmin->getRoles();
        if (!in_array('ROLE_ADMIN', $permisos)) {
            return $this->json([
                'message' => 'No tienes permisos'
            ]);
        }

        $email = $request->get('oldEmail');
        $new_email = $request->get('newEmail');
        $user = $userRepository->findOneBy(['email' => $email]);
        if (!$user) {
            return $this->json([
                'message' => 'Usuario no encontrado'
            ]);
        }
        $user->setEmail($new_email);
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->flush();
        return $this->json([
            'message' => 'Correo electrónico cambiado con éxito'
        ]);
    }


    #[Route('/register', name: 'new_user', methods: ['POST'])]
    public function register(Request $request, UserRepository $userRepository, ManagerRegistry $doctrine, UserPasswordHasherInterface $passwordHasher)
    {
        //el request está en json

        $request = $this->transformJsonBody($request);
        //obtener el mail y el password del request
        $email = $request->get('email');
        $password = $request->get('password');
        $name = $request->get('name');
        $surname = $request->get('surname');

        $user = $userRepository->findOneBy(['email' => $email]);

        if ($user) {
            return $this->json([
                'message' => 'El usuario ya existe'
            ], 400);
        }

        //crear el usuario
        $user = new User();
        $user->setEmail($email);
        $user->setName($name);
        $user->setSurname($surname);
        $user->setUuid(\Symfony\Component\Uid\Uuid::v4());
        $user->setPassword($passwordHasher->hashPassword($user, $password));

        //add user consent

        $em = $doctrine->getManager();
        $this->darConsentimiento('CerebroDev', $em, $user);
        $this->darConsentimiento('Moodle', $em, $user);
        $this->darConsentimiento('WoocomerceGenotipia', $em, $user);

        $em->flush();

        //enviar mail de confirmación
        /*
        $year = date("Y");
        $url = 'https://oauth.genotipia.com/public/index.php/authorize?response_type=code&client_id=CerebroDev&redirect_uri='.$_ENV['URL_REDIRECT'].'&scope=profile%20email';
        $message = (new Email())
            ->from('genotipia-test@test-quasardynamics.company')
            ->to($email)
            ->subject('Confirmación de registro')
            ->html(
                $this->renderView(
                    'emails/confirmacion_registro.html.twig',
                    [
                    'name' => $user->getName(),
                    'pass' => $password,
                    'year' => $year,
                    'url' => $url]
                ),
                'text/html');
                
        $mailer->send($message);

*/


        //retornar el usuario
        return $this->json($user);
    }

    #[Route('/public/recover', name: 'recover_account', methods: ['POST'])]
    public function recoverAccount(Request $request, UserRepository $userRepository, RecoverAccountRepository $recoverAccountRepository, ManagerRegistry $doctrine, MailerInterface $mailer)
    {
        $request = $this->transformJsonBody($request);

        $email = $request->get('email');

        $user = $userRepository->findOneBy(['email' => $email]);
        if (!$user) {
            return $this->json([
                'message' => 'Datos inválidos'
            ], 404);
        }

        $em = $doctrine->getManager();
        list($url, $date, $token) = $recoverAccountRepository->getRecoverData($email);
        $recoverAccount = new RecoverAccount();
        $recoverAccount
            ->setRecoveryToken($token)
            ->setEmail($email)
            ->setDate($date)
            ->setUsed(false);
        $em->persist($recoverAccount);
        $em->flush();

        // $email = "iamvaldidev@gmail.com";

        $message = (new Email())
            ->from('genotipia-test@test-quasardynamics.company')
            ->to($email)
            ->subject('Recupera tu cuenta de Genotipia')
            ->html(
                $this->renderView(
                    'emails/recover_account.html.twig',
                    ['recoveryUrl' => $url]
                ),
                'text/html'
            );
        $mailer->send($message);

        return $this->json([
            'message' => 'Correo electrónico enviado con éxito'
        ]);
    }

    #[Route('/public/change/password', name: 'public_change_password', methods: ['POST'])]
    public function publicChangePassword(Request $request, ManagerRegistry $doctrine, RecoverAccountRepository $recoverAccountRepository, UserPasswordHasherInterface $passwordHasher, UserRepository $userRepository)
    {
        $request = $this->transformJsonBody($request);
        $recover_token = $request->get('recover_token');
        $new_password = $request->get('new_password');

        $recoverAccount = $recoverAccountRepository->findOneBy(['recoveryToken' => $recover_token, 'used' => false]);
        if (!$recoverAccount) {
            return $this->json([
                'message' => 'Datos inválidos'
            ], 422);
        }

        list($data, $iv) = explode('|', $recover_token);
        $iv = base64_decode($iv);
        $decrypted = openssl_decrypt($data, "AES-256-CBC", "t%~B^g%Q~Q]2Aw6S%V;R2DJnXj*Xcm2{#3y6+\^-Ts~:K*Kq^g5!Pj.~6F~R.>m#", 0, $iv);
        if (!$decrypted) {
            return $this->json([
                'message' => 'Datos inválidos'
            ], 422);
        }

        list($email, $date) = explode('___', $decrypted);
        $user = $userRepository->findOneBy(['email' => $email]);
        if (!$user) {
            return $this->json([
                'message' => 'Datos inválidos'
            ], 422);
        }

        if (intval($date) < time()) {
            return $this->json([
                'message' => 'El token ha expirado'
            ], 422);
        }

        $user->setPassword($passwordHasher->hashPassword($user, $new_password));
        $recoverAccount->setUsed(true);
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->persist($recoverAccount);
        $em->flush();
        return $this->json([
            'message' => 'Contraseña cambiada con éxito'
        ]);
    }

    private function darConsentimiento($cliente, $em, $user)
    {
        $userConsent = new \App\Entity\OAuth2UserConsent();
        $userConsent->setUser($user);
        $appClient = $em->getRepository(Client::class)->findOneBy(['identifier' => $cliente]);
        if ($appClient) {
            //add cliente a user consent
            $userConsent->setClient($appClient);
        }
        $userConsent->setScopes(['blog_read', 'openid', 'profile', 'email']);
        $userConsent->setCreated(new \DateTimeImmutable());

        $user->addOAuth2UserConsent($userConsent);

        //guardar el usuario
        $em->persist($user);
        $em->persist($userConsent);
    }

    #[Route('.well-known/jwks.json', name: 'app_jwks', methods: ['GET'])]
    public function jwks(): Response
    {
        // Load the public key from the filesystem and use OpenSSL to parse it.
        $kernelDirectory = $this->getParameter('kernel.project_dir');
        $publicKey = openssl_pkey_get_public(file_get_contents($kernelDirectory . '/var/keys/public.key'));
        $details = openssl_pkey_get_details($publicKey);
        $jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'use' => 'sig',
                    'kid' => '1',
                    'n' => strtr(rtrim(base64_encode($details['rsa']['n']), '='), '+/', '-_'),
                    'e' => strtr(rtrim(base64_encode($details['rsa']['e']), '='), '+/', '-_'),
                ],
            ],
        ];
        return $this->json($jwks);
    }
    protected function transformJsonBody(\Symfony\Component\HttpFoundation\Request $request)
    {
        $data = json_decode($request->getContent(), true);

        if ($data === null) {
            return $request;
        }

        $request->request->replace($data);

        return $request;
    }


    #[Route('/api/change/password', name: 'change_password', methods: ['POST'])]
    public function changePassword(Request $request, ManagerRegistry $doctrine, UserPasswordHasherInterface $passwordHasher)
    {
        $request = $this->transformJsonBody($request);
        $password = $request->get('password');
        $userInterface = $this->getUser();
        $user = $doctrine->getRepository(User::class)->findOneBy(array('uuid' => $userInterface->getUserIdentifier()));
        if (!$user) {
            return $this->json([
                'message' => 'Usuario no encontrado'
            ]);
        }
        $user->setPassword($passwordHasher->hashPassword($user, $password));
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->flush();
        return $this->json([
            'message' => 'Contraseña actualizada con éxito!'
        ]);
    }

    #[Route('/user', name: 'delete_user', methods: ['DELETE'])]
    public function deleteUser(Request $request, UserRepository $userRepository)
    {
        //TODO poner ip de la api
        /*
        $ip = $request->getClientIp();
        if($ip != 'ip api'){
            return $this->json([
                'message' => 'You do not have permissions to do this!'
            ], 403);
        }*/
        $claveSecreta = $request->headers->get('authorization');
        if (!$claveSecreta || $claveSecreta != '!CUKJ56*>Olq*0@dkD3Prq2g') {
            return $this->json([
                'message' => 'No tienes permisos'
            ], 403);
        }
        $request = $this->transformJsonBody($request);
        $mail = $request->get('email');
        $user = $userRepository->findOneBy(array('email' => $mail));
        if (!$user) {
            return $this->json([
                'message' => 'Usuario no encontrado'
            ], 404);
        }
        $userRepository->remove($user, true);
        return $this->json([
            'message' => 'Usuario borrado con éxito'
        ]);
    }

    #[Route('/api/generate/password', name: 'generate_password', methods: ['POST'])]
    public function generatePassword(Request $request, ManagerRegistry $doctrine, UserPasswordHasherInterface $passwordHasher, MailerInterface $mailer)
    {
        $request = $this->transformJsonBody($request);
        $userAdmin = $this->getUser();
        $permisos = $userAdmin->getRoles();
        if (!in_array('ROLE_ADMIN', $permisos)) {
            return $this->json([
                'message' => 'No tienes permisos'
            ]);
        }
        $email = $request->get('email');
        $user = $doctrine->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            return $this->json([
                'message' => 'Usuario no encontrado'
            ]);
        }
        //generar password
        $password = substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 8);
        $user->setPassword($passwordHasher->hashPassword($user, $password));
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->flush();

        //enviar email con la nueva contraseña
        $message = (new Email())
            // TODO: cambiar el email
            ->from('genotipia-test@test-quasardynamics.company')
            ->to($email)
            ->subject('Nueva contraseña')
            ->html(
                $this->renderView(
                    'emails/new_password.html.twig',
                    ['password' => $password]
                ),
                'text/html'
            );
        //$mailer = $this->get('mailer');
        $mailer->send($message);

        return $this->json([
            'message' => 'Contraseña cambiada con éxito'
        ]);
    }
}
