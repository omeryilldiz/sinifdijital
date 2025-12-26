# Tümleyici Olay (Complement Event)

## Tanım
Bir olayın **tümleyeni**, o olayın gerçekleşmediği durumlardır. $A$ olayının tümleyeni $A'$ (veya $\bar{A}$ veya $A^c$) ile gösterilir.

<!-- Küme diyagramı: burada görüntü olarak yer alacak -->
\begin{tikzpicture}[scale=1.2]
  % Örnek uzay
  \draw[thick] (0,0) rectangle (4,2.5);
  % Olay A (dolu daire)
  \fill[blue!30] (2,1.25) circle (0.9);
  \draw[thick,blue] (2,1.25) circle (0.9);
  % Etiketler
  \node[blue,font=\Large\bfseries] at (2,1.25) {A};
  \node[font=\Large] at (0.6,2.05) {$A'$};
  \node[font=\Large] at (3.6,2.2) {S};
  % Formül alt etiketi
  \node[font=\Large] at (2,-0.5) {$P(A) + P(A') = 1$};
\end{tikzpicture}

## Temel Özellikler

- **Örnek Uzay (S):** Tüm olası sonuçların kümesi
- **Olay A:** Mavi daire ile gösterilen bölge
- **Tümleyici Olay (A'):** Mavi dairenin dışında kalan bölge
- **Temel Bağıntı:** $P(A) + P(A') = 1$

## Formüller

\[
P(A') = 1 - P(A)
\]

\[
P(A) = 1 - P(A')
\]

## Örnek 1
Bir zarın atılması deneyinde:
- $A$: Çift sayı gelmesi olayı $= \{2, 4, 6\}$ 
- $P(A) = \frac{3}{6} = \frac{1}{2}$
- $A'$: Tek sayı gelmesi olayı $= \{1, 3, 5\}$
- $P(A') = 1 - \frac{1}{2} = \frac{1}{2}$

## Örnek 2
Bir torbada 3 kırmızı, 5 mavi top vardır:
- $A$: Kırmızı top çekme olayı
- $P(A) = \frac{3}{8}$
- $A'$: Mavi top çekme olayı
- $P(A') = 1 - \frac{3}{8} = \frac{5}{8}$

> Önemli Not: Bir olay ile tümleyeni birbirini dışlar (kesişimleri boş küme) ve birlikte örnek uzayı oluştururlar:  
> \(A \cap A' = \emptyset\) ve \(A \cup A' = S\)
