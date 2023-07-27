<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\Persistence\ManagerRegistry;
use League\Bundle\OAuth2ServerBundle\Repository\ClientRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

class IndexController extends AbstractController
{
    #[Route('/', name: 'app_index')]
    public function index(): Response
    {
        return $this->render('index/index.html.twig', [
            'controller_name' => 'IndexController',
        ]);
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
            'name' => $user->getEmail(),
            'apellido' => 'Perez'
        ]);
    }

    
    #[Route('/register', name: 'new_user', methods: ['POST'])]
    public function register(Request $request, ManagerRegistry $doctrine, UserPasswordHasherInterface $passwordHasher, ClientRepository $clientRepository)
    {
        //el request está en json
        
        $request = $this->transformJsonBody($request);
        //obtener el mail y el password del request
        $email = $request->get('email');
        $password = $request->get('password');
        //crear el usuario
        $user = new User();
        $user->setEmail($email);
        $user->setUuid(\Symfony\Component\Uid\Uuid::v4());
        $user->setPassword($passwordHasher->hashPassword($user, $password));

        //add user consent
        
        $userConsent = new \App\Entity\OAuth2UserConsent();
        $userConsent->setUser($user);
        $cliente = $clientRepository->getClientEntity('CerebroDev');
        $em = $doctrine->getManager();
        $appClient = $em->getRepository(Client::class)->findOneBy(['identifier' =>'CerebroDev']);
        if($appClient){
            //add cliente a user consent
            $userConsent->setClient($appClient);
        }
        $userConsent->setScopes(['profile','email']);
        $userConsent->setCreated(new \DateTimeImmutable());

        $user->addOAuth2UserConsent($userConsent);

        //guardar el usuario
        $em->persist($user);
        $em->persist($userConsent);
        $em->flush();
        //retornar el usuario
        return $this->json($user);
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
