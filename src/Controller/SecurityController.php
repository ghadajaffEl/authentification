<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Repository\UserRepository;
use App\Service\Mailer;
use Doctrine\Common\Persistence\ObjectManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    /**
     * @Route("/login", name="app_login")
     */
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new \Exception('Will be intercepted before getting here');
    }

    /**
     * @Route("/register", name="app_register")
     */
    public function register(Request $request, UserPasswordEncoderInterface $encoder, ObjectManager $manager, Mailer $mailer)
    {
        $user = new User();
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $user->setPassword($encoder->encodePassword($user, $user->getPassword()));
            $user->setRoles(["ROLE_ADMIN"]);
            $user->setIsActivated(false);
            $token = bin2hex(random_bytes(50));
            $user->setToken($token);
            $manager->persist($user);
            $manager->flush();
            $body = $this->renderView('Mail/mailCreateAccount.html.twig',
                ['user' => $user, 'token' => $token]);
            $mailer->sendMail($user->getEmail(), 'registration', $body);
            $this->addFlash('success', 'veuillez vérifier votre email pour activer votre compte.');
            return $this->redirectToRoute("app_login");

        }

        return $this->render('security/register.html.twig', ['form' => $form->createView()]);
    }

    /**
     * @Route("/check-activation/{token}",name="check-activation")
     */
    public function checkActivation($token, UserRepository $userRepository, ObjectManager $manager)
    {
        if ($user = $userRepository->findOneBy(['token' => $token])) {

            $user->setIsActivated(true);
            $user->setToken('');
            $manager->flush();
            $this->addFlash('success', 'votre compte est activé.');
        }else{
            $this->addFlash('error', 'lien invalid.');
        }
        return $this->redirectToRoute('app_login');
    }
}
