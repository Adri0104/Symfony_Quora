<?php

namespace App\Controller;

use App\Entity\ResetPassword;
use App\Repository\ResetPasswordRepository;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class SecurityController extends AbstractController
{
    #[Route(path: '/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    #[Route(path: '/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    #[Route('/reset-password/{token}', name: 'reset-password')]
    public function resetPassword(RateLimiterFactory $passwordRecoveryLimiter, UserPasswordHasherInterface $userPasswordHasher, Request $request, EntityManagerInterface $em, string $token, ResetPasswordRepository $resetPasswordRepository)
    {
        $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
        if (false === $limiter->consume(1)->isAccepted()) {
            $this->addFlash('error', 'Vous devez attendre une heure pour refaire une récupération');
            return $this->redirectToRoute('app_login');
        }

        $resetPassword = $resetPasswordRepository->findOneBy(['token' => sha1($token)]);
        if (!$resetPassword || $resetPassword->getExpiredAt() < new \DateTime('now')) {
            if ($resetPassword) {
                $em->remove($resetPassword);
                $em->flush();
            }
            $this->addFlash('error', 'Votre demande est expirée veuillez refaire une demande.');
            return $this->redirectToRoute('app_login');
        }

        $passwordForm = $this->createFormBuilder()
            ->add('password', PasswordType::class, [
                'label' => 'Nouveau mot de passe',
                'constraints' => [
                    new Length([
                        'min' => 6,
                        'minMessage' => 'Le mot de passe doit faire au moins 6 caractères.'
                    ]),
                    new NotBlank([
                        'message' => 'Veuillez renseigner un mot de passe.'
                    ])
                ]
            ])
            ->getForm();

        $passwordForm->handleRequest($request);
        if ($passwordForm->isSubmitted() && $passwordForm->isValid()) {
            $password = $passwordForm->get('password')->getData();
            $user = $resetPassword->getUser();
            $hash = $userPasswordHasher->hashPassword($user, $password);
            $user->setPassword($hash);
            $em->remove($resetPassword);
            $em->flush();
            $this->addFlash('success', 'Votre mot de passe a été modifié.');
            return $this->redirectToRoute('app_login');
        }

        return $this->render('security/reset_password_form.html.twig', [
            'form' => $passwordForm->createView()
        ]);
    }

    #[Route('/reset-password-request', name: 'reset-password-request')]
    public function resetPasswordRequest(RateLimiterFactory $passwordRecoveryLimiter, MailerInterface $mailer, Request $request, UserRepository $userRepository, ResetPasswordRepository $resetPasswordRepository, EntityManagerInterface $em)
    {
        $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
        if (false === $limiter->consume(1)->isAccepted()) {
            $this->addFlash('error', 'Vous devez attendre une heure pour refaire une récupération');
            return $this->redirectToRoute('app_login');
        }

        $emailForm = $this->createFormBuilder()->add('email', EmailType::class, [
            'constraints' => [
                new NotBlank([
                    'message' => 'Veuillez renseigner votre email'
                ])
            ]
        ])->getForm();
        $emailForm->handleRequest($request);
        if ($emailForm->isSubmitted() && $emailForm->isValid()) {
            $emailValue = $emailForm->get('email')->getData();
            $user = $userRepository->findOneBy(['email' => $emailValue]);
            if ($user) {
                $oldResetPassword = $resetPasswordRepository->findOneBy(['user' => $user]);
                if ($oldResetPassword) {
                    $em->remove($oldResetPassword);
                    $em->flush();
                }
                $resetPassword = new ResetPassword();
                $resetPassword->setUser($user);
                $resetPassword->setExpiredAt(new \DateTimeImmutable('+2 hours'));
                $token = substr(str_replace(['+', '/', '='], '', base64_encode(random_bytes(30))), 0, 20);
                $resetPassword->setToken(sha1($token));
                $em->persist($resetPassword);
                $em->flush();
                $email = new TemplatedEmail();
                $email->to($emailValue)
                    ->subject('Demande de réinitialisation de mot de passe')
                    ->htmlTemplate('@email_templates/reset_password_request.html.twig')
                    ->context([
                        'token' => $token
                    ]);
                $mailer->send($email);
            }
            $this->addFlash('success', 'Un email vous a été envoyé pour réinitialiser votre mot de passe');
            return $this->redirectToRoute('app_home');
        }

        return $this->render('security/reset_password_request.html.twig', [
            'form' => $emailForm->createView()
        ]);
    }

}
