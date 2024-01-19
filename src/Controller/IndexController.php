<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\Persistence\ManagerRegistry;
use League\Bundle\OAuth2ServerBundle\Repository\ClientRepository;
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
        
        $redireccion->setTargetUrl('https://oauth.genotipia.com/public/index.php/authorize?response_type=code&client_id=CerebroDev&redirect_uri='.$_ENV['URL_REDIRECT'].'&scope=profile%20email');
        return $redireccion;
    }

    #[Route('/api/test', name: 'app_api_test')]
    public function apiTest(): Response
    {
        /** @var User $user */
        $user = $this->getUser();
        return $this->json([
            'message' => 'You successfully authenticated!',
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
        if(!$authorization){
            return $this->json([
                'message' => 'You do not have permissions to do this!'
            ]);
        }
        if("!CUKJ56*>Olq*0@dkD3Prq2g" != $authorization){
            return $this->json([
                'message' => 'You do not have permissions to do this!'
            ]);
        }

        $request = $this->transformJsonBody($request);
        
        $email = $request->get('oldEmail');
        $new_email = $request->get('newEmail');
        $user = $userRepository->findOneBy(['email' => $email]);
        if(!$user){
            return $this->json([
                'message' => 'User not found!'
            ]);
        }
        $user->setEmail($new_email);
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->flush();
        return $this->json([
            'message' => 'You successfully changed your email!'
        ]);
    }
    
    #[Route('/api/change-mail', name: 'app_change_mail', methods: ['POST'])]
    public function apiChangeMail(Request $request, ManagerRegistry $doctrine, UserRepository $userRepository): Response
    {
        $request = $this->transformJsonBody($request);
        
        $userAdmin = $this->getUser();
        $permisos = $userAdmin->getRoles();
        if(!in_array('ROLE_ADMIN', $permisos)){
            return $this->json([
                'message' => 'You do not have permissions to do this!'
            ]);
        }
        
        $email = $request->get('oldEmail');
        $new_email = $request->get('newEmail');
        $user = $userRepository->findOneBy(['email' => $email]);
        if(!$user){
            return $this->json([
                'message' => 'User not found!'
            ]);
        }
        $user->setEmail($new_email);
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->flush();
        return $this->json([
            'message' => 'You successfully changed your email!'
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

        if($user){
            return $this->json([
                'message' => 'User already exists!'
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
            ->from('noreply@grupomemorable.com')
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

    private function darConsentimiento($cliente, $em, $user){
        $userConsent = new \App\Entity\OAuth2UserConsent();
        $userConsent->setUser($user);
        $appClient = $em->getRepository(Client::class)->findOneBy(['identifier' =>$cliente]);
        if($appClient){
            //add cliente a user consent
            $userConsent->setClient($appClient);
        }
        $userConsent->setScopes(['blog_read','openid','profile','email']);
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
        $user = $doctrine->getRepository(User::class)->findOneBy(array('uuid' =>$userInterface->getUserIdentifier()));
        if(!$user){
            return $this->json([
                'message' => 'User not found!'
            ]);
        }
        $user->setPassword($passwordHasher->hashPassword($user, $password));
        $em = $doctrine->getManager();
        $em->persist($user);
        $em->flush();
        return $this->json([
            'message' => 'You password was changed successfully!'
        ]);
    }

    #[Route('/user', name: 'delete_user', methods: ['DELETE'])]
    public function deleteUser(Request $request, UserRepository $userRepository, ManagerRegistry $doctrine)
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
        if(!$claveSecreta || $claveSecreta != '!CUKJ56*>Olq*0@dkD3Prq2g'){
            return $this->json([
                'message' => 'You do not have permissions to do this!'
            ], 403);
        }
        $request = $this->transformJsonBody($request);
        $mail = $request->get('email');
        $user = $userRepository->findOneBy(array('email' =>$mail));
        if(!$user){
            return $this->json([
                'message' => 'User not found!'
            ],404);
        }
        $em = $doctrine->getManager();
        $em->remove($user);
        $em->flush();
        return $this->json([
            'message' => 'You user was deleted successfully!'
        ]);
    }
    
    #[Route('/api/generate/password', name: 'generate_password', methods: ['POST'])]
    public function generatePassword(Request $request, ManagerRegistry $doctrine, UserPasswordHasherInterface $passwordHasher,MailerInterface $mailer)
    {
        $request = $this->transformJsonBody($request);
        $userAdmin = $this->getUser();
        $permisos = $userAdmin->getRoles();
        if(!in_array('ROLE_ADMIN', $permisos)){
            return $this->json([
                'message' => 'You do not have permissions to do this!'
            ]);
        }
        $email = $request->get('email');
        $user = $doctrine->getRepository(User::class)->findOneBy(['email' => $email]);
        if(!$user){
            return $this->json([
                'message' => 'User not found!'
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
            ->from('noreply@grupomemorable.com')
            ->to($email)
            ->subject('New password')
            ->html(
                $this->renderView(
                    'emails/new_password.html.twig',
                    ['password' => $password]
                ),
                'text/html');
        //$mailer = $this->get('mailer');
        $mailer->send($message);

        return $this->json([
            'message' => 'The password was changed successfully!'
        ]);
    }
    
}
