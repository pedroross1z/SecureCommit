# Licença — Software Livre

Oi! Antes de qualquer coisa jurídica chata, deixa eu te contar o que esse
projeto é e por que ele existe assim, aberto pra todo mundo.

O **Secure Commit** nasceu como um trabalho de faculdade, mas virou uma coisa
que eu quis fazer com carinho — uma plataforma de segurança de aplicações
(ASPM) que qualquer pessoa, estudante, professor, dev curioso ou empresa
pequena, pudesse pegar, estudar, mexer e usar. Não faz sentido pra mim
trancar isso num cofre. Segurança da informação já tem barreira demais pra
quem tá começando; não vou ser eu a colocar mais uma.

Então eu libero o código como **software livre**. E software livre, pra quem
nunca ouviu o termo, não é só "de graça". É sobre liberdade mesmo. Você tem
quatro liberdades aqui, e elas valem pra qualquer pessoa que receba uma cópia
desse código:

1. **Liberdade de usar.** Rode esse software pra qualquer coisa que você
   quiser. No seu PC, no seu servidor, na sua empresa, na sua aula, no seu
   TCC, num CTF, num hackathon. Não precisa pedir licença, não precisa
   avisar, não precisa pagar nada.

2. **Liberdade de estudar.** O código tá aqui, aberto. Lê, entende, aprende,
   quebra, conserta. Se tiver uma linha que te deixou confuso, abre uma
   issue — a ideia é justamente que esse projeto sirva pra alguém aprender
   como um ASPM funciona por dentro.

3. **Liberdade de modificar.** Pega esse código e muda o que quiser. Adapta
   pra sua stack, troca o Semgrep por outro scanner, bota outro LLM no lugar
   do Claude, reescreve o frontend em Vue — vai fundo. É seu.

4. **Liberdade de redistribuir.** Pode compartilhar o código original ou a
   sua versão modificada com quem você quiser. Com um amigo, com a sala, com
   a internet inteira. Só te peço uma coisa: **mantenha essa mesma liberdade
   pra quem receber de você**. Se você mexeu e tá distribuindo, publique as
   suas mudanças também sob essa mesma licença, pra próxima pessoa continuar
   livre do mesmo jeito. É o que a galera chama de *copyleft* — a liberdade
   que você recebeu, você passa adiante.

---

## A parte formal (porque o mundo é o que é)

Esse projeto é distribuído sob os termos da **GNU General Public License
versão 3 (GPLv3)** ou qualquer versão posterior, à sua escolha. O texto
oficial e completo da licença está em:

https://www.gnu.org/licenses/gpl-3.0.txt

Se houver qualquer conflito entre o que eu escrevi aqui em português e o
texto oficial da GPLv3 em inglês, **o texto oficial prevalece**. Eu não sou
advogado; a conversa acima é pra ser humana, não pra substituir a licença.

Copyright (C) 2026 Pedro Rossi

Este programa é software livre: você pode redistribuí-lo e/ou modificá-lo
sob os termos da Licença Pública Geral GNU, conforme publicada pela Free
Software Foundation, na versão 3 da Licença, ou (a seu critério) qualquer
versão posterior.

Este programa é distribuído na esperança de que seja útil, mas **SEM
NENHUMA GARANTIA**; sem sequer a garantia implícita de COMERCIABILIDADE ou
ADEQUAÇÃO A UM PROPÓSITO ESPECÍFICO. Veja a Licença Pública Geral GNU para
mais detalhes.

---

## Um último aviso, de coração

Esse projeto é educacional. Ele usa scanners de segurança reais (Semgrep,
Trivy, Gitleaks, OWASP ZAP) e um LLM pra ajudar na triagem, mas **não
substitui um programa de segurança profissional**. Não roda isso achando que
tá cobrindo compliance de verdade sem antes entender os limites. Se você for
usar em produção, por favor leia o código, entenda o que ele faz, e assuma a
responsabilidade pelo que decidir.

E se esse projeto te ajudou de alguma forma — num TCC, numa aula, numa
curiosidade — manda um oi. Vai fazer meu dia.

Pedro Rossi
pedrorossidemac09@gmail.com
